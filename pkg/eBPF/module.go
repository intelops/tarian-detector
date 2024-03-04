// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package ebpf

import (
	"github.com/intelops/tarian-detector/pkg/err"
)

var moduleErr = err.New("ebpf.module")

// EbpfModule represents an eBPF module.
type EbpfModule interface {
	// GetModule is a method that returns a pointer to a Module and an error.
	GetModule() (*Module, error)
}

// Module represents a module containing eBPF programs and maps.
type Module struct {
	name     string         // Name of the module.
	programs []*ProgramInfo // Slice of eBPF program information.
	ebpfMap  *MapInfo       // Information about the eBPF map.
}

// NewModule creates a new eBPF module with the given name.
func NewModule(n string) *Module {
	return &Module{
		name:     n,
		programs: make([]*ProgramInfo, 0),
		ebpfMap:  nil,
	}
}

// AddProgram appends an eBPF program to the module's list of programs.
func (m *Module) AddProgram(prog *ProgramInfo) {
	m.programs = append(m.programs, prog)
}

// Map sets the eBPF map for the module..
func (m *Module) Map(mp *MapInfo) {
	m.ebpfMap = mp
}

// Prepare initializes the module and returns a handler along with any errors encountered.
func (m *Module) Prepare() (*Handler, error) {
	// Create a new handler with the provided module name.
	handler := NewHandler(m.name)

	// Attach programs to the kernel hook points
	for _, prog := range m.programs {
		hook := prog.hook

		if !prog.shouldAttach {
			continue
		}

		pL, err := hook.AttachProbe(prog.name)
		if err != nil {
			return nil, moduleErr.Throwf("%v", err)
		}

		handler.AddProbeLink(pL)
	}

	// Create map reader to receive data from the kernel
	if m.ebpfMap != nil {
		mrs, err := m.ebpfMap.CreateReaders()
		if err != nil {
			return nil, moduleErr.Throwf("%v", err)
		}

		handler.AddMapReaders(mrs)
	}

	return handler, nil
}

// GetName returns the name of the Module.
func (m *Module) GetName() string {
	return m.name
}

// GetPrograms returns the slice of programs in the module.
func (m *Module) GetPrograms() []*ProgramInfo {
	return m.programs
}

// GetMap returns the ebpfMap of the Module.
func (m *Module) GetMap() *MapInfo {
	return m.ebpfMap
}
