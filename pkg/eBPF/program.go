// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package ebpf

import "github.com/cilium/ebpf"

// ProgramInfo represents information about an eBPF program.
type ProgramInfo struct {
	name         *ebpf.Program // Pointer to the eBPF program.
	hook         *HookInfo     // Pointer to the associated hook information.
	shouldAttach bool          // Indicates whether the program should be attached.
}

// NewProgram creates a new ProgramInfo instance.
func NewProgram(n *ebpf.Program, h *HookInfo) *ProgramInfo {
	return &ProgramInfo{
		name:         n,
		hook:         h,
		shouldAttach: true,
	}
}

// Enable sets the shouldAttach flag to true and returns the updated ProgramInfo.
func (pi *ProgramInfo) Enable() *ProgramInfo {
	pi.shouldAttach = true

	return pi
}

// Disable sets shouldAttach flag to false and returns the updated ProgramInfo.
func (pi *ProgramInfo) Disable() *ProgramInfo {
	pi.shouldAttach = false

	return pi
}

// GetHook returns the HookInfo associated with the ProgramInfo.
func (pi *ProgramInfo) GetHook() *HookInfo {
	return pi.hook
}

// GetName returns the name of the program.
func (pi *ProgramInfo) GetName() *ebpf.Program {
	return pi.name
}

// GetShouldAttach returns the value of shouldAttach for the ProgramInfo struct
func (pi *ProgramInfo) GetShouldAttach() bool {
	return pi.shouldAttach
}
