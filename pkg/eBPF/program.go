// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package ebpf

import "github.com/cilium/ebpf"

type ProgramInfo struct {
	name         *ebpf.Program
	hook         *HookInfo
	shouldAttach bool
}

func NewProgram(n *ebpf.Program, h *HookInfo) *ProgramInfo {
	return &ProgramInfo{
		name:         n,
		hook:         h,
		shouldAttach: true,
	}
}

func (pi *ProgramInfo) Enable() *ProgramInfo {
	pi.shouldAttach = true

	return pi
}

func (pi *ProgramInfo) Disable() *ProgramInfo {
	pi.shouldAttach = false

	return pi
}
