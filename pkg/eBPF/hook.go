// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/intelops/tarian-detector/pkg/err"
)

var hookErr = err.New("ebpf.hook")

// HookInfoType is an integer type used to represent different types of eBPF hooks.
type HookInfoType int

// HookInfo struct contains information about an eBPF hook.
type HookInfo struct {
	hookType HookInfoType // Type of the eBPF hook
	group    string       // Group name, required for Tracepoint type hooks
	name     string       // Name of the hook
	opts     any          // Options for the hook, varies based on the hook type
}

// Constants representing different types of eBPF hooks.
const (
	Tracepoint HookInfoType = iota
	RawTracepoint
	Kprobe
	Kretprobe
	Cgroup
)

const (
	ErrInvalidBpfHookType               string = "invalid BPF hook type: %v"
	ErrMissingOptionsForBpfHookType     string = "missing field %s for the BPF Hook: %v"
	ErrInvalidOptionsTypeForBpfHookType string = "unexpected 'Opts' field type detected in the BPF Hook. Expected type: %T, Received type: %T"
)

// NewHookInfo creates a new HookInfo instance with default values.
func NewHookInfo() *HookInfo {
	return &HookInfo{
		name:     "",
		group:    "",
		opts:     nil,
		hookType: -1,
	}
}

// Tracepoint sets the HookInfo instance to represent a Tracepoint type hook.
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

// RawTracepoint sets the HookInfo instance to represent a RawTracepoint type hook.
func (hi *HookInfo) RawTracepoint(op link.RawTracepointOptions) *HookInfo {
	hi.hookType = RawTracepoint
	hi.opts = op

	return hi
}

// Kprobe sets the HookInfo instance to represent a Kprobe type hook.
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

// Kretprobe sets the HookInfo instance to represent a Kretprobe type hook.
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

// Cgroup sets the HookInfo instance to represent a Cgroup type hook.
func (hi *HookInfo) Cgroup(op link.CgroupOptions) *HookInfo {
	hi.hookType = Cgroup
	hi.opts = op

	return hi
}

// AttachProbe attaches the eBPF program to the hook represented by the HookInfo instance.
func (hi *HookInfo) AttachProbe(programName *ebpf.Program) (link.Link, error) {
	switch hi.hookType {
	case Tracepoint:
		if len(hi.name) == 0 {
			return nil, hookErr.Throwf(ErrMissingOptionsForBpfHookType, "'Name'", hi.hookType)
		}

		if len(hi.group) == 0 {
			return nil, hookErr.Throwf(ErrMissingOptionsForBpfHookType, "'Group'", hi.hookType)
		}

		opts, ok := hi.opts.(*link.TracepointOptions)
		if !ok {
			return nil, hookErr.Throwf(ErrInvalidOptionsTypeForBpfHookType, &link.TracepointOptions{}, hi.opts)
		}

		return link.Tracepoint(hi.group, hi.name, programName, opts)
	case RawTracepoint:
		opts, ok := hi.opts.(link.RawTracepointOptions)
		if !ok {
			return nil, hookErr.Throwf(ErrInvalidOptionsTypeForBpfHookType, link.RawTracepointOptions{}, hi.opts)
		}

		return link.AttachRawTracepoint(opts)
	case Kprobe, Kretprobe:
		if len(hi.name) == 0 {
			return nil, hookErr.Throwf(ErrMissingOptionsForBpfHookType, "'Name'", hi.hookType)
		}

		opts, ok := hi.opts.(*link.KprobeOptions)
		if !ok {
			return nil, hookErr.Throwf(ErrInvalidOptionsTypeForBpfHookType, &link.KprobeOptions{}, hi.opts)
		}

		if hi.hookType == Kprobe {
			return link.Kprobe(hi.name, programName, opts)
		} else {
			return link.Kretprobe(hi.name, programName, opts)
		}
	case Cgroup:
		opts, ok := hi.opts.(link.CgroupOptions)
		if !ok {
			return nil, hookErr.Throwf(ErrInvalidOptionsTypeForBpfHookType, link.CgroupOptions{}, hi.opts)
		}

		return link.AttachCgroup(opts)
	default:
		return nil, hookErr.Throwf(ErrInvalidBpfHookType, hi.hookType)
	}
}

// detachProbes detaches all the probes represented by the links in the provided slice.
func detachProbes(lns []link.Link) error {
	for _, l := range lns {
		err := detachProbe(l)
		if err != nil {
			return hookErr.Throwf("%v", err)
		}
	}

	return nil
}

// detachProbe detaches the probe represented by the provided link.
func detachProbe(l link.Link) error {
	return l.Close()
}

// GetHookType returns the type of the hook represented by the HookInfo instance.
func (hi *HookInfo) GetHookType() HookInfoType {
	return hi.hookType
}

// GetHookName returns the name of the hook represented by the HookInfo instance.
func (hi *HookInfo) GetHookName() string {
	return hi.name
}

// GetHookGroup returns the group of the hook represented by the HookInfo instance.
func (hi *HookInfo) GetHookGroup() string {
	return hi.group
}

// GetOptions returns the opts of the hook represented by the HookInfo instance.
func (hi *HookInfo) GetOptions() interface{} {
	return hi.opts
}

// String method for the HookInfoType type. It returns a string representation of the HookInfoType.
func (hit HookInfoType) String() string {
	switch hit {
	case Tracepoint:
		return "Tracepoint"
	case RawTracepoint:
		return "RawTracepoint"
	case Kprobe:
		return "Kprobe"
	case Kretprobe:
		return "Kretprobe"
	case Cgroup:
		return "Cgroup"
	default:
		return fmt.Sprintf("unknown HookInfoType(%d)", int(hit))
	}
}
