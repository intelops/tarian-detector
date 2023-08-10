// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package ebpf_manager

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/intelops/tarian-detector/pkg/inspector/detector"
)

type EbpfProgram interface {
	NewEbpf() (Program, error)              // tells how create a ebpf program.
	DataParser(any) (map[string]any, error) // tells how data received from ebpf program should be parsed
}

type HookType int

// Predefined hooks
const (
	Tracepoint HookType = iota
	RawTracepoint
	Kprobe
	Kretprobe
	Cgroup
)

type Hook struct {
	Type  HookType
	Group string // HookType: Tracepoint needs this Field
	Name  string
	Opts  any // expected values with relavant hook type: cilium/ebpf/link.*TracepointOptions | RawTracepointOptions | *KprobeOptions | .*KprobeOptions | .KprobeMultiOptions | .*KprobeOptions | .*TracepointOptions
}

type Program struct {
	Name    string
	Hook    Hook
	Program *ebpf.Program
	Map     *ebpf.Map
	Data    any
}

type EbpfHandler struct {
	dataParser func(any) (map[string]any, error)
	mapReader  *ringbuf.Reader
	ebpfLink   link.Link
	dataType   any
}

type EbpfPrograms struct {
	ebpf_programs   []EbpfProgram
	event_detectors []detector.EventDetector
}

// Creates new instance of type *EbpfPrograms
func NewEbpfProgram() *EbpfPrograms {
	return &EbpfPrograms{
		ebpf_programs:   make([]EbpfProgram, 0),
		event_detectors: make([]detector.EventDetector, 0),
	}
}

// add ebpf program to EbpfPrograms
func (e *EbpfPrograms) Add(program EbpfProgram) {
	e.ebpf_programs = append(e.ebpf_programs, program)
}

// remove memory lock and attaches all the ebpf programs to kernel and
// creates map and returns the references to maps and hooks in the form of detector.
func (e *EbpfPrograms) LoadPrograms() ([]detector.EventDetector, error) {
	err := rlimit.RemoveMemlock()
	if err != nil {
		return nil, err
	}

	for _, ebpf_program := range e.ebpf_programs {
		ep, err := ebpf_program.NewEbpf()
		if err != nil {
			return nil, err
		}

		eh, err := ep.attach()
		if err != nil {
			return nil, err
		}

		eh.dataParser = ebpf_program.DataParser

		event_detector := detector.EventDetector{}
		event_detector.Start = eh.read
		event_detector.Close = eh.close

		e.event_detectors = append(e.event_detectors, event_detector)
	}

	return e.event_detectors, nil
}

// attaches ebpf program to kernel and returns reference to it.
func (ep *Program) attachHook() (link.Link, error) {
	var hook_link link.Link
	var err error

	switch ep.Hook.Type {
	case Tracepoint:
		var opts *link.TracepointOptions
		if ep.Hook.Opts != nil {
			opts = ep.Hook.Opts.(*link.TracepointOptions)
		} else {
			opts = nil
		}

		hook_link, err = link.Tracepoint(ep.Hook.Group, ep.Hook.Name, ep.Program, opts)
	case RawTracepoint:
		var opts link.RawTracepointOptions
		if ep.Hook.Opts != nil {
			opts = ep.Hook.Opts.(link.RawTracepointOptions)
		} else {
			return nil, fmt.Errorf("opts cannot be nil for Hook.Type: RawTracepoint")
		}
		hook_link, err = link.AttachRawTracepoint(opts)
	case Kprobe:
		var opts *link.KprobeOptions
		if ep.Hook.Opts != nil {
			opts = ep.Hook.Opts.(*link.KprobeOptions)
		} else {
			opts = nil
		}
		hook_link, err = link.Kprobe(ep.Hook.Name, ep.Program, opts)
	case Kretprobe:
		var opts *link.KprobeOptions
		if ep.Hook.Opts != nil {
			opts = ep.Hook.Opts.(*link.KprobeOptions)
		} else {
			opts = nil
		}
		hook_link, err = link.Kretprobe(ep.Hook.Name, ep.Program, opts)
	case Cgroup:
		var opts link.CgroupOptions
		if ep.Hook.Opts != nil {
			opts = ep.Hook.Opts.(link.CgroupOptions)
		} else {
			return nil, fmt.Errorf("opts cannot be nil for Hook.Type: Cgroup")
		}
		hook_link, err = link.AttachCgroup(opts)
	default:
		return nil, fmt.Errorf("invalid hook type value: %v", ep.Hook.Type)
	}

	return hook_link, err
}

// instantiate the map
func (ep *Program) attachMap() (*ringbuf.Reader, error) {
	return ringbuf.NewReader(ep.Map)
}

// attaches the ebpf program to kernel
func (ep *Program) attach() (*EbpfHandler, error) {
	var err error
	eh := EbpfHandler{}

	eh.ebpfLink, err = ep.attachHook()
	if err != nil {
		return nil, err
	}

	eh.mapReader, err = ep.attachMap()
	if err != nil {
		return nil, err
	}

	eh.dataType = ep.Data

	return &eh, nil
}

// reads the information from maps.
func (ep *EbpfHandler) read() (map[string]any, error) {
	record, err := ep.mapReader.Read()
	if err != nil {
		return nil, err
	}

	err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, ep.dataType)
	if err != nil {
		return nil, err
	}

	return ep.dataParser(ep.dataType)
}

// closes the maps and hooks
func (ep *EbpfHandler) close() error {
	err := ep.ebpfLink.Close()
	if err != nil {
		return err
	}

	return ep.mapReader.Close()
}
