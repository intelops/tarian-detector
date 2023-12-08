// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package ebpf

import "github.com/cilium/ebpf"

type ProgramInfo struct {
	Name         *ebpf.Program
	Hook         *HookInfo
	ShouldAttach bool
}

func NewProgram(n *ebpf.Program, h *HookInfo) *ProgramInfo {
	return &ProgramInfo{
		Name:         n,
		Hook:         h,
		ShouldAttach: true,
	}
}

func (pi *ProgramInfo) Enable() {
	pi.ShouldAttach = true
}

func (pi *ProgramInfo) Disable() {
	pi.ShouldAttach = false
}
