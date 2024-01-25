// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package eventparser

import (
	"fmt"
)

type arg struct {
	Name  string
	Value string
}

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

func LoadTarianEvents() {
	Events = GenerateTarianEvents()
}

func GenerateTarianEvents() TarianEventMap {
	events := make(TarianEventMap)

	execve_e := NewTarianEvent(59, "sys_execve_entry", 8957,
		Param{name: "filename", paramType: TDT_STR},
		Param{name: "argv", paramType: TDT_STR_ARR},
		Param{name: "envp", paramType: TDT_STR_ARR},
	)
	events.AddTarianEvent(TDE_SYSCALL_EXECVE_E, execve_e)

	execve_r := NewTarianEvent(59, "sys_execve_exit", 765,
		Param{name: "return", paramType: TDT_S32},
	)
	events.AddTarianEvent(TDE_SYSCALL_EXECVE_R, execve_r)

	execveat_e := NewTarianEvent(322, "sys_execveat_entry", 8965,
		Param{name: "fd", paramType: TDT_S32, function: parseExecveatDird},
		Param{name: "filename", paramType: TDT_STR},
		Param{name: "argv", paramType: TDT_STR_ARR},
		Param{name: "envp", paramType: TDT_STR_ARR},
		Param{name: "flags", paramType: TDT_S32, function: parseExecveatFlags},
	)
	events.AddTarianEvent(TDE_SYSCALL_EXECVEAT_E, execveat_e)

	execveat_r := NewTarianEvent(322, "sys_execveat_exit", 765,
		Param{name: "return", paramType: TDT_S32},
	)
	events.AddTarianEvent(TDE_SYSCALL_EXECVEAT_R, execveat_r)

	clone_e := NewTarianEvent(56, "sys_clone_entry", 793,
		Param{name: "clone_flags", paramType: TDT_U64, function: parseCloneFlags},
		Param{name: "newsp", paramType: TDT_S64},
		Param{name: "parent_tid", paramType: TDT_S32},
		Param{name: "child_tid", paramType: TDT_S32},
		Param{name: "tls", paramType: TDT_S64},
	)
	events.AddTarianEvent(TDE_SYSCALL_CLONE_E, clone_e)

	clone_r := NewTarianEvent(56, "sys_clone_exit", 765,
		Param{name: "return", paramType: TDT_S32},
	)
	events.AddTarianEvent(TDE_SYSCALL_CLONE_R, clone_r)

	close_e := NewTarianEvent(3, "sys_close_entry", 765,
		Param{name: "fd", paramType: TDT_S32},
	)
	events.AddTarianEvent(TDE_SYSCALL_CLOSE_E, close_e)

	return events
}

func (p *Param) processValue(val interface{}) (arg, error) {
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
