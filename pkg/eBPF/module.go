// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package ebpf

import (
	"github.com/intelops/tarian-detector/pkg/err"
)

type EbpfModule interface {
	GetModule() (*Module, error)
}

type Module struct {
	name     string
	programs []*ProgramInfo
	ebpfMap  *MapInfo
}

var moduleErr = err.New("ebpf.Module")

func NewModule(n string) *Module {
	return &Module{
		name:     n,
		programs: make([]*ProgramInfo, 0),
		ebpfMap:  nil,
	}
}

func (m *Module) AddProgram(prog *ProgramInfo) {
	m.programs = append(m.programs, prog)
}

func (m *Module) Map(mp *MapInfo) {
	m.ebpfMap = mp
}

func (m *Module) Prepare() (*Handler, error) {
	handler := NewHandler(m.name)

	/*
	*
	* attachs programs to the kernel hook points
	*
	 */
	for _, prog := range m.programs {
		if !prog.shouldAttach {
			continue
		}

		pL, err := prog.hook.AttachProbe(prog.name)
		if err != nil {
			return nil, moduleErr.Throwf("%v", err)
		}

		handler.AddProbeLink(pL)
	}

	/*
	*
	* creates map reader to receive data from kernel
	*
	 */
	mrs, err := m.ebpfMap.CreateReaders()
	if err != nil {
		return nil, moduleErr.Throwf("%v", err)
	}

	handler.AddMapReaders(mrs)

	return handler, nil
}