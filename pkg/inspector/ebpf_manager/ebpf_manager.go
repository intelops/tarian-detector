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
	NewEbpf() (EbpfModule, error)           // tells how create a ebpf program.
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
	Id           string
	Hook         Hook
	Program      *ebpf.Program
	ShouldAttach bool
}
type EbpfModule struct {
	Programs []Program
	Map      *ebpf.Map
	Data     any
}

type EbpfHandler struct {
	dataParser func(any) (map[string]any, error)
	mapReader  *ringbuf.Reader
	ebpfLinks  []link.Link
	dataType   any
}

type EbpfPrograms struct {
	ebpf_programs   []EbpfProgram
	event_detectors []detector.EventDetector
}

// Creates new instance of type *EbpfPrograms
func NewEbpfPrograms() *EbpfPrograms {
	return &EbpfPrograms{
		ebpf_programs:   make([]EbpfProgram, 0),
		event_detectors: make([]detector.EventDetector, 0),
	}
}

// add ebpf program to EbpfPrograms
func (eps *EbpfPrograms) Add(module EbpfProgram) {
	eps.ebpf_programs = append(eps.ebpf_programs, module)
}

// remove memory lock and attaches all the ebpf programs to kernel and
// creates map and returns the references to maps and hooks in the form of detector.
func (eps *EbpfPrograms) LoadPrograms() ([]detector.EventDetector, error) {
	err := rlimit.RemoveMemlock()
	if err != nil {
		return nil, err
	}

	for _, ebpf_program := range eps.ebpf_programs {
		em, err := ebpf_program.NewEbpf()
		if err != nil {
			return nil, err
		}

		eh, err := em.attach()
		if err != nil {
			return nil, err
		}
		eh.dataParser = ebpf_program.DataParser

		if len(eh.ebpfLinks) <= 0 {
			continue
		}

		event_detector := detector.EventDetector{}
		event_detector.Start = eh.read
		event_detector.Close = eh.close

		eps.event_detectors = append(eps.event_detectors, event_detector)
	}

	return eps.event_detectors, nil
}

// attaches ebpf program to kernel and returns reference to it.
func (p *Program) attachHook() (link.Link, error) {
	var hook_link link.Link
	var err error

	switch p.Hook.Type {
	case Tracepoint:
		var opts *link.TracepointOptions
		if p.Hook.Opts != nil {
			opts = p.Hook.Opts.(*link.TracepointOptions)
		} else {
			opts = nil
		}

		hook_link, err = link.Tracepoint(p.Hook.Group, p.Hook.Name, p.Program, opts)
	case RawTracepoint:
		var opts link.RawTracepointOptions
		if p.Hook.Opts != nil {
			opts = p.Hook.Opts.(link.RawTracepointOptions)
		} else {
			return nil, fmt.Errorf("opts cannot be nil for Hook.Type: RawTracepoint")
		}

		hook_link, err = link.AttachRawTracepoint(opts)
	case Kprobe:
		var opts *link.KprobeOptions
		if p.Hook.Opts != nil {
			opts = p.Hook.Opts.(*link.KprobeOptions)
		} else {
			opts = nil
		}

		hook_link, err = link.Kprobe(p.Hook.Name, p.Program, opts)
	case Kretprobe:
		var opts *link.KprobeOptions
		if p.Hook.Opts != nil {
			opts = p.Hook.Opts.(*link.KprobeOptions)
		} else {
			opts = nil
		}

		hook_link, err = link.Kretprobe(p.Hook.Name, p.Program, opts)
	case Cgroup:
		var opts link.CgroupOptions
		if p.Hook.Opts != nil {
			opts = p.Hook.Opts.(link.CgroupOptions)
		} else {
			return nil, fmt.Errorf("opts cannot be nil for Hook.Type: Cgroup")
		}

		hook_link, err = link.AttachCgroup(opts)
	default:
		return nil, fmt.Errorf("invalid hook type value: %v", p.Hook.Type)
	}

	return hook_link, err
}

// instantiate the map
func (em *EbpfModule) attachMap() (*ringbuf.Reader, error) {
	return ringbuf.NewReader(em.Map)
}

// attaches the ebpf program to kernel
func (em *EbpfModule) attach() (*EbpfHandler, error) {
	var err error
	eh := EbpfHandler{}

	for _, program := range em.Programs {
		if !program.ShouldAttach {
			continue
		}

		temp_link, err := program.attachHook()
		if err != nil {
			return nil, err
		}

		eh.ebpfLinks = append(eh.ebpfLinks, temp_link)
	}

	eh.mapReader, err = em.attachMap()
	if err != nil {
		return nil, err
	}

	eh.dataType = em.Data

	return &eh, nil
}

// reads the information from maps.
func (eh *EbpfHandler) read() (map[string]any, error) {
	record, err := eh.mapReader.Read()
	if err != nil {
		return nil, err
	}

	err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, eh.dataType)
	if err != nil {
		return nil, err
	}

	return eh.dataParser(eh.dataType)
}

// closes the maps and hooks
func (eh *EbpfHandler) close() error {
	for _, lnk := range eh.ebpfLinks {
		err := lnk.Close()
		if err != nil {
			return err
		}
	}

	return eh.mapReader.Close()
}
