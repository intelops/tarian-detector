// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package eventparser

import (
	"fmt"
)

type Param struct {
	name        string
	description string
	paramType   TarianParamType
	linuxType   string
	function    func(any) (string, error)
}

type TarianEvent struct {
	name        string
	syscallId   int
	description string
	eventSize   uint32
	params      []Param
}

type TarianEventMap map[int]TarianEvent

func (te TarianEventMap) AddTarianEvent(idx int, event TarianEvent) {
	te[idx] = event
}

func NewTarianEvent(id int, name string, size uint32, params ...Param) TarianEvent {
	return TarianEvent{
		name:      name,
		syscallId: id,
		eventSize: size,
		params:    params,
	}
}

type arg struct {
	Name  string
	Value string
}

func LoadTarianEvents() {
	Events = GenerateTarianEvents()
}

func GenerateTarianEvents() TarianEventMap {
	events := make(TarianEventMap)

	execve_e := NewTarianEvent(59, "sys_execve_entry", 8700,
		Param{name: "filename", paramType: TDT_STR},
		Param{name: "argv", paramType: TDT_STR_ARR},
		Param{name: "envp", paramType: TDT_STR_ARR},
	)
	events.AddTarianEvent(TDE_SYSCALL_EXECVE_E, execve_e)

	execve_r := NewTarianEvent(59, "sys_execve_exit", 508,
		Param{name: "return", paramType: TDT_S32},
	)
	events.AddTarianEvent(TDE_SYSCALL_EXECVE_R, execve_r)

	return events
}

func (p *Param) ParseArg(val interface{}) (arg, error) {
	arg := arg{}

	if p.function != nil {
		parsedValue, err := p.function(val)
		if err != nil {
			return arg, err
		}
		arg.Value = parsedValue
	} else {
		arg.Value = fmt.Sprintf("%v", val)
	}

	arg.Name = p.name

	return arg, nil
}
