// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/intelops/tarian-detector/pkg/err"
)

type HookInfoType int

type HookInfo struct {
	Type  HookInfoType
	Group string // HookInfoType: Tracepoint needs this Field
	Name  string
	Opts  any // expected values with relavant hook type: cilium/ebpf/link.*TracepointOptions | .RawTracepointOptions | .*KprobeOptions | .CgroupOptions
}

// Supported ebpf hooks
const (
	Tracepoint HookInfoType = iota
	RawTracepoint
	Kprobe
	Kretprobe
	Cgroup
)

const (
	ErrInvalidBpfHookType               string = "invalid BPF hook type: %v"
	ErrMissingOptionsForBpfHookType            = "missing field %s for the BPF Hook: %v"
	ErrInvalidOptionsTypeForBpfHookType        = "unexpected 'Opts' field type detected in the BPF Hook. Expected type: %T, Received type: %T"
)

var hookErr = err.New("ebpf.Hook")

func NewHookInfo() *HookInfo {
	return &HookInfo{
		Name:  "",
		Group: "",
		Opts:  nil,
		Type:  -1,
	}
}

func (hi *HookInfo) Tracepoint(g string, n string, op ...*link.TracepointOptions) *HookInfo {
	if len(op) > 0 {
		hi.Opts = op[0]
	} else {
		hi.Opts = &link.TracepointOptions{}
	}

	hi.Type = Tracepoint
	hi.Name = n
	hi.Group = g

	return hi
}

func (hi *HookInfo) RawTracepoint(op link.RawTracepointOptions) *HookInfo {
	hi.Type = RawTracepoint
	hi.Opts = op

	return hi
}

func (hi *HookInfo) Kprobe(n string, op ...*link.KprobeOptions) *HookInfo {
	if len(op) > 0 {
		hi.Opts = op[0]
	} else {
		hi.Opts = &link.KprobeOptions{}
	}

	hi.Type = Kprobe
	hi.Name = n

	return hi
}

func (hi *HookInfo) Kretprobe(n string, op ...*link.KprobeOptions) *HookInfo {
	if len(op) > 0 {
		hi.Opts = op[0]
	} else {
		hi.Opts = &link.KprobeOptions{}
	}

	hi.Type = Kretprobe
	hi.Name = n

	return hi
}

func (hi *HookInfo) Cgroup(op link.CgroupOptions) *HookInfo {
	hi.Type = Cgroup
	hi.Opts = op

	return hi
}

func (hi *HookInfo) AttachProbe(programName *ebpf.Program) (link.Link, error) {
	switch hi.Type {
	case Tracepoint:
		if len(hi.Name) == 0 {
			return nil, hookErr.Throwf(ErrMissingOptionsForBpfHookType, "'Name'", hi.Type)
		}

		if len(hi.Group) == 0 {
			return nil, hookErr.Throwf(ErrMissingOptionsForBpfHookType, "'Group'", hi.Type)
		}

		if isValid := areTypesEqual(hi.Opts, &link.TracepointOptions{}); !isValid {
			return nil, hookErr.Throwf(ErrInvalidOptionsTypeForBpfHookType, &link.TracepointOptions{}, hi.Opts)
		}

		return link.Tracepoint(hi.Group, hi.Name, programName, hi.Opts.(*link.TracepointOptions))
	case RawTracepoint:
		if hi.Opts == nil {
			return nil, hookErr.Throwf(ErrMissingOptionsForBpfHookType, "'Opts'", hi.Type)
		}

		if isValid := areTypesEqual(hi.Opts, link.RawTracepointOptions{}); !isValid {
			return nil, hookErr.Throwf(ErrInvalidOptionsTypeForBpfHookType, link.RawTracepointOptions{}, hi.Opts)
		}

		return link.AttachRawTracepoint(hi.Opts.(link.RawTracepointOptions))
	case Kprobe, Kretprobe:
		if len(hi.Name) == 0 {
			return nil, hookErr.Throwf(ErrMissingOptionsForBpfHookType, "'Name'", hi.Type)
		}

		if isValid := areTypesEqual(hi.Opts, &link.KprobeOptions{}); !isValid {
			return nil, hookErr.Throwf(ErrInvalidOptionsTypeForBpfHookType, &link.KprobeOptions{}, hi.Opts)
		}

		return link.Kprobe(hi.Name, programName, hi.Opts.(*link.KprobeOptions))
	case Cgroup:
		if hi.Opts == nil {
			return nil, hookErr.Throwf(ErrMissingOptionsForBpfHookType, "'Opts'", hi.Type)
		}

		if isValid := areTypesEqual(hi.Opts, link.CgroupOptions{}); !isValid {
			return nil, hookErr.Throwf(ErrInvalidOptionsTypeForBpfHookType, link.CgroupOptions{}, hi.Opts)
		}

		return link.AttachCgroup(hi.Opts.(link.CgroupOptions))
	default:
		return nil, hookErr.Throwf(ErrInvalidBpfHookType, hi.Type)
	}
}

func areTypesEqual(current any, expected any) bool {
	return fmt.Sprintf("%T", current) == fmt.Sprintf("%T", expected)
}

func detachProbes(lns []link.Link) error {
	for _, l := range lns {
		err := detachProbe(l)
		if err != nil {
			return hookErr.Throwf("%v", err)
		}
	}

	return nil
}

func detachProbe(l link.Link) error {
	return l.Close()
}
