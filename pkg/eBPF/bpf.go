// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Module interface {
	NewModule() (BpfModule, error) // tells how create a ebpf module.
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

type BpfProgram struct {
	Id           string
	Hook         Hook
	Name         *ebpf.Program
	ShouldAttach bool
}

type BpfModule struct {
	Id       string
	Programs []BpfProgram
	Map      *ebpf.Map
}

type Handler struct {
	Id         string
	MapReader  *ringbuf.Reader
	ProbeLinks []link.Link
}

func NewBpfModule() BpfModule {
	return BpfModule{
		Programs: make([]BpfProgram, 0),
	}
}

func (bp *BpfProgram) AttachProbe() (link.Link, error) {
	var l link.Link
	var err error

	probe := bp.Hook

	switch probe.Type {
	case Tracepoint:
		var opts *link.TracepointOptions
		if probe.Opts != nil {
			opts = probe.Opts.(*link.TracepointOptions)
		} else {
			opts = nil
		}
		l, err = link.Tracepoint(probe.Group, probe.Name, bp.Name, opts)
	case RawTracepoint:
		var opts link.RawTracepointOptions
		if probe.Opts != nil {
			opts = probe.Opts.(link.RawTracepointOptions)
		} else {
			return nil, fmt.Errorf("opts cannot be nil for Hook.Type: RawTracepoint")
		}

		l, err = link.AttachRawTracepoint(opts)
	case Kprobe:
		var opts *link.KprobeOptions
		if probe.Opts != nil {
			opts = probe.Opts.(*link.KprobeOptions)
		} else {
			opts = nil
		}

		l, err = link.Kprobe(probe.Name, bp.Name, opts)
	case Kretprobe:
		var opts *link.KprobeOptions
		if probe.Opts != nil {
			opts = probe.Opts.(*link.KprobeOptions)
		} else {
			opts = nil
		}

		l, err = link.Kretprobe(probe.Name, bp.Name, opts)
	case Cgroup:
		var opts link.CgroupOptions
		if probe.Opts != nil {
			opts = probe.Opts.(link.CgroupOptions)
		} else {
			return nil, fmt.Errorf("opts cannot be nil for Hook.Type: Cgroup")
		}

		l, err = link.AttachCgroup(opts)
	default:
		return nil, fmt.Errorf("invalid hook type value: %v", probe.Type)
	}

	return l, err
}

func (bm *BpfModule) Start() (*Handler, error) {
	var handler Handler
	var err error

	handler.Id = bm.Id
	for _, prog := range bm.Programs {
		if !prog.ShouldAttach {
			continue
		}

		pL, err := prog.AttachProbe()
		if err != nil {
			return nil, err
		}

		handler.ProbeLinks = append(handler.ProbeLinks, pL)
	}

	handler.MapReader, err = createMapReader(bm.Map)
	if err != nil {
		return nil, err
	}

	return &handler, nil
}

func (h *Handler) ReadAsInterface() ([]byte, error) {
	record, err := h.MapReader.Read()
	if err != nil {
		return []byte{}, err
	}

	return record.RawSample, nil
}

func (h *Handler) Close() error {
	for _, link := range h.ProbeLinks {
		err := link.Close()
		if err != nil {
			return err
		}
	}

	return h.MapReader.Close()
}

func createMapReader(name *ebpf.Map) (*ringbuf.Reader, error) {
	return ringbuf.NewReader(name)
}
