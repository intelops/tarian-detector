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
	hookType HookInfoType
	group    string // HookInfoType: Tracepoint needs this Field
	name     string
	opts     any // expected values with relavant hook type: cilium/ebpf/link.*TracepointOptions | .RawTracepointOptions | .*KprobeOptions | .CgroupOptions
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
		name:     "",
		group:    "",
		opts:     nil,
		hookType: -1,
	}
}

func (hi *HookInfo) Tracepoint(g string, n string, op ...*link.TracepointOptions) *HookInfo {
	if len(op) > 0 {
		hi.opts = op[0]
	} else {
		hi.opts = &link.TracepointOptions{}
	}

	hi.hookType = Tracepoint
	hi.name = n
	hi.group = g

	return hi
}

func (hi *HookInfo) RawTracepoint(op link.RawTracepointOptions) *HookInfo {
	hi.hookType = RawTracepoint
	hi.opts = op

	return hi
}

func (hi *HookInfo) Kprobe(n string, op ...*link.KprobeOptions) *HookInfo {
	if len(op) > 0 {
		hi.opts = op[0]
	} else {
		hi.opts = &link.KprobeOptions{}
	}

	hi.hookType = Kprobe
	hi.name = n

	return hi
}

func (hi *HookInfo) Kretprobe(n string, op ...*link.KprobeOptions) *HookInfo {
	if len(op) > 0 {
		hi.opts = op[0]
	} else {
		hi.opts = &link.KprobeOptions{}
	}

	hi.hookType = Kretprobe
	hi.name = n

	return hi
}

func (hi *HookInfo) Cgroup(op link.CgroupOptions) *HookInfo {
	hi.hookType = Cgroup
	hi.opts = op

	return hi
}

func (hi *HookInfo) AttachProbe(programName *ebpf.Program) (link.Link, error) {
	switch hi.hookType {
	case Tracepoint:
		if len(hi.name) == 0 {
			return nil, hookErr.Throwf(ErrMissingOptionsForBpfHookType, "'Name'", hi.hookType)
		}

		if len(hi.group) == 0 {
			return nil, hookErr.Throwf(ErrMissingOptionsForBpfHookType, "'Group'", hi.hookType)
		}

		if isValid := areTypesEqual(hi.opts, &link.TracepointOptions{}); !isValid {
			return nil, hookErr.Throwf(ErrInvalidOptionsTypeForBpfHookType, &link.TracepointOptions{}, hi.opts)
		}

		return link.Tracepoint(hi.group, hi.name, programName, hi.opts.(*link.TracepointOptions))
	case RawTracepoint:
		if hi.opts == nil {
			return nil, hookErr.Throwf(ErrMissingOptionsForBpfHookType, "'Opts'", hi.hookType)
		}

		if isValid := areTypesEqual(hi.opts, link.RawTracepointOptions{}); !isValid {
			return nil, hookErr.Throwf(ErrInvalidOptionsTypeForBpfHookType, link.RawTracepointOptions{}, hi.opts)
		}

		return link.AttachRawTracepoint(hi.opts.(link.RawTracepointOptions))
	case Kprobe, Kretprobe:
		if len(hi.name) == 0 {
			return nil, hookErr.Throwf(ErrMissingOptionsForBpfHookType, "'Name'", hi.hookType)
		}

		if isValid := areTypesEqual(hi.opts, &link.KprobeOptions{}); !isValid {
			return nil, hookErr.Throwf(ErrInvalidOptionsTypeForBpfHookType, &link.KprobeOptions{}, hi.opts)
		}

		return link.Kprobe(hi.name, programName, hi.opts.(*link.KprobeOptions))
	case Cgroup:
		if hi.opts == nil {
			return nil, hookErr.Throwf(ErrMissingOptionsForBpfHookType, "'Opts'", hi.hookType)
		}

		if isValid := areTypesEqual(hi.opts, link.CgroupOptions{}); !isValid {
			return nil, hookErr.Throwf(ErrInvalidOptionsTypeForBpfHookType, link.CgroupOptions{}, hi.opts)
		}

		return link.AttachCgroup(hi.opts.(link.CgroupOptions))
	default:
		return nil, hookErr.Throwf(ErrInvalidBpfHookType, hi.hookType)
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
