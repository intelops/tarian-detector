// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package ebpf

import (
	"github.com/intelops/tarian-detector/pkg/err"
)

type Module struct {
	Name     string
	Programs []*ProgramInfo
	Map      *MapInfo
}

var moduleErr = err.New("ebpf.Module")

func NewModule(n string) *Module {
	return &Module{
		Name:     n,
		Programs: make([]*ProgramInfo, 0),
		Map:      nil,
	}
}

func (m *Module) AddProgram(prog *ProgramInfo) {
	m.Programs = append(m.Programs, prog)
}

func (m *Module) Prepare() (*Handler, error) {
	handler := NewHandler(m.Name)

	for _, prog := range m.Programs {
		if !prog.ShouldAttach {
			continue
		}

		pL, err := prog.Hook.AttachProbe(prog.Name)
		if err != nil {
			return nil, moduleErr.Throwf("%v", err)
		}

		handler.AddProbeLink(pL)
	}

	mrs, err := m.Map.CreateReaders()
	if err != nil {
		return nil, moduleErr.Throwf("%v", err)
	}

	handler.AddMapReaders(mrs)

	return handler, nil
}
