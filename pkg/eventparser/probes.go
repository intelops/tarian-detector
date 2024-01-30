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

	close_r := NewTarianEvent(3, "sys_close_exit", 765,
		Param{name: "return", paramType: TDT_S32},
	)
	events.AddTarianEvent(TDE_SYSCALL_CLOSE_R, close_r)

	read_e := NewTarianEvent(0, "sys_read_entry", 4867,
		Param{name: "fd", paramType: TDT_S32},
		Param{name: "buf", paramType: TDT_BYTE_ARR},
		Param{name: "count", paramType: TDT_U32},
	)
	events.AddTarianEvent(TDE_SYSCALL_READ_E, read_e)

	read_r := NewTarianEvent(0, "sys_read_exit", 769,
		Param{name: "return", paramType: TDT_S64},
	)
	events.AddTarianEvent(TDE_SYSCALL_READ_R, read_r)

	write_e := NewTarianEvent(1, "sys_write_entry", 4867,
		Param{name: "fd", paramType: TDT_S32},
		Param{name: "buf", paramType: TDT_BYTE_ARR},
		Param{name: "count", paramType: TDT_U32},
	)
	events.AddTarianEvent(TDE_SYSCALL_WRITE_E, write_e)

	write_r := NewTarianEvent(1, "sys_write_exit", 769,
		Param{name: "return", paramType: TDT_S64},
	)
	events.AddTarianEvent(TDE_SYSCALL_WRITE_R, write_r)

	open_e := NewTarianEvent(2, "sys_open_entry", 4867,
		Param{name: "filename", paramType: TDT_STR},
		Param{name: "flags", paramType: TDT_S32, function: parseOpenFlags},
		Param{name: "mode", paramType: TDT_U32, function: parseOpenMode},
	)
	events.AddTarianEvent(TDE_SYSCALL_OPEN_E, open_e)

	open_r := NewTarianEvent(2, "sys_open_exit", 765,
		Param{name: "return", paramType: TDT_U32},
	)
	events.AddTarianEvent(TDE_SYSCALL_OPEN_R, open_r)

	readv_e := NewTarianEvent(19, "sys_readv_entry", 4867,
		Param{name: "fd", paramType: TDT_S32},
		// Param{name: "vec", paramType: TDT_STR},
		Param{name: "vlen", paramType: TDT_S32},
	)
	events.AddTarianEvent(TDE_SYSCALL_READV_E, readv_e)

	readv_r := NewTarianEvent(19, "sys_readv_exit", 769,
		Param{name: "return", paramType: TDT_S64},
	)
	events.AddTarianEvent(TDE_SYSCALL_READV_R, readv_r)

	writev_e := NewTarianEvent(20, "sys_writev_entry", 4867,
		Param{name: "fd", paramType: TDT_S32},
		// Param{name: "vec", paramType: TDT_STR},
		Param{name: "vlen", paramType: TDT_S32},
	)
	events.AddTarianEvent(TDE_SYSCALL_WRITEV_E, writev_e)

	writev_r := NewTarianEvent(20, "sys_writev_exit", 769,
		Param{name: "return", paramType: TDT_S64},
	)
	events.AddTarianEvent(TDE_SYSCALL_WRITEV_R, writev_r)

	openat_e := NewTarianEvent(257, "sys_openat_entry", 4867,
		Param{name: "dfd", paramType: TDT_S32, function: parseExecveatDird},
		Param{name: "filename", paramType: TDT_STR},
		Param{name: "flags", paramType: TDT_S32, function: parseOpenFlags},
		Param{name: "mode", paramType: TDT_U32, function: parseOpenMode},
	)
	events.AddTarianEvent(TDE_SYSCALL_OPENAT_E, openat_e)

	openat_r := NewTarianEvent(257, "sys_openat_exit", 765,
		Param{name: "return", paramType: TDT_U32},
	)
	events.AddTarianEvent(TDE_SYSCALL_OPENAT_R, openat_r)

	openat2_e := NewTarianEvent(437, "sys_openat2_entry", 4867,
		Param{name: "dfd", paramType: TDT_S32, function: parseExecveatDird},
		Param{name: "filename", paramType: TDT_STR},
		Param{name: "flags", paramType: TDT_S64, function: parseOpenat2Flags},
		Param{name: "mode", paramType: TDT_S64, function: parseOpenat2Mode},
		Param{name: "resolve", paramType: TDT_S64, function: parseOpenat2Resolve},
		Param{name: "usize", paramType: TDT_S32},
	)
	events.AddTarianEvent(TDE_SYSCALL_OPENAT2_E, openat2_e)

	openat2_r := NewTarianEvent(437, "sys_openat2_exit", 769,
		Param{name: "return", paramType: TDT_S64},
	)
	events.AddTarianEvent(TDE_SYSCALL_OPENAT2_R, openat2_r)

	listen_e := NewTarianEvent(50, "sys_listen_entry", 769,
		Param{name: "fd", paramType: TDT_S32},
		Param{name: "backlog", paramType: TDT_S32},
	)
	events.AddTarianEvent(TDE_SYSCALL_LISTEN_E, listen_e)

	listen_r := NewTarianEvent(50, "sys_listen_exit", 765,
		Param{name: "return", paramType: TDT_S32},
	)
	events.AddTarianEvent(TDE_SYSCALL_LISTEN_R, listen_r)

	socket_e := NewTarianEvent(41, "sys_socket_entry", 773,
		Param{name: "family", paramType: TDT_S32, function: parseSocketFamily},
		Param{name: "type", paramType: TDT_S32, function: parseSocketType},
		Param{name: "protocol", paramType: TDT_S32, function: parseSocketProtocol},
	)
	events.AddTarianEvent(TDE_SYSCALL_SOCKET_E, socket_e)

	socket_r := NewTarianEvent(41, "sys_socket_exit", 765,
		Param{name: "return", paramType: TDT_S32},
	)
	events.AddTarianEvent(TDE_SYSCALL_SOCKET_R, socket_r)

	accept_e := NewTarianEvent(43, "sys_accept_entry", 773,
		Param{name: "fd", paramType: TDT_S32},
		Param{name: "upper_addrlen", paramType: TDT_S32},
	)
	events.AddTarianEvent(TDE_SYSCALL_ACCEPT_E, accept_e)

	accept_r := NewTarianEvent(43, "sys_accept_exit", 765,
		Param{name: "return", paramType: TDT_S32},
	)
	events.AddTarianEvent(TDE_SYSCALL_ACCEPT_R, accept_r)

	bind_e := NewTarianEvent(49, "sys_bind_entry", 773,
		Param{name: "fd", paramType: TDT_S32},
		Param{name: "addrlen", paramType: TDT_S32},
	)
	events.AddTarianEvent(TDE_SYSCALL_BIND_E, bind_e)

	bind_r := NewTarianEvent(49, "sys_bind_exit", 765,
		Param{name: "return", paramType: TDT_S32},
	)
	events.AddTarianEvent(TDE_SYSCALL_BIND_R, bind_r)

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
