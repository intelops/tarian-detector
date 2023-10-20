// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package eventparser

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/intelops/tarian-detector/pkg/utils"
)

const (
	noneT = iota
	intT
	uintT
	longT
	ulongT
	strT
	strArrT
)

type Event struct {
	buffer     []byte
	cursor     int
	fieldCount uint8
}

type RawArgInfo struct {
	Index uint8  // index of field
	Type  uint8  // Type of the field (e.g., "int", "string", "long")
	Size  int    // size of field in bytes
	Value []byte // Actual value of the field as a byte slice
}

func New(rawBuffer []byte, count uint8) *Event {
	return &Event{
		buffer:     rawBuffer,
		cursor:     0,
		fieldCount: count,
	}
}

func DecodeByte(b []byte) (map[string]any, error) {
	var event_data map[string]any = make(map[string]any)

	var ec EventContext
	err := binary.Read(bytes.NewReader(b), binary.LittleEndian, &ec)
	if err != nil {
		return map[string]any{}, err
	}

	event_data["ts"] = ec.Context.Ts
	event_data["start_time"] = ec.Context.Task.StartTime
	event_data["host_pid"] = ec.Context.Task.HostPid
	event_data["host_tgid"] = ec.Context.Task.HostTgid
	event_data["host_ppid"] = ec.Context.Task.HostPpid
	event_data["pid"] = ec.Context.Task.Pid
	event_data["tgid"] = ec.Context.Task.Tgid
	event_data["ppid"] = ec.Context.Task.Ppid
	event_data["uid"] = ec.Context.Task.Uid
	event_data["gid"] = ec.Context.Task.Gid
	event_data["cgroup_id"] = ec.Context.Task.CgroupId
	event_data["mount_ns_id"] = ec.Context.Task.MountNsId
	event_data["pid_ns_id"] = ec.Context.Task.PidNsId
	event_data["comm"] = utils.ToString(ec.Context.Task.Comm[:])

	cwd_idx, err := utils.Uint16(ec.Context.Task.Cwd[:2])
	if err != nil {
		return map[string]any{}, nil
	}

	cwd_sz, err := utils.Uint16(ec.Context.Task.Cwd[2:4])
	if err != nil {
		return map[string]any{}, nil
	}

	event_data["cwd"] = utils.ToString(ec.Context.Task.Cwd[cwd_idx : cwd_idx+cwd_sz])

	event_data["event_id"] = ec.Context.EventId
	event_data["syscall"] = ec.Context.Syscall
	event_data["processor_id"] = ec.Context.ProcessorId

	event_data["sysname"] = utils.ToString(ec.SystemInfo.Sysname[:])
	event_data["nodename"] = utils.ToString(ec.SystemInfo.Nodename[:])
	event_data["release"] = utils.ToString(ec.SystemInfo.Release[:])
	event_data["version"] = utils.ToString(ec.SystemInfo.Version[:])
	event_data["machine"] = utils.ToString(ec.SystemInfo.Machine[:])
	event_data["domain_name"] = utils.ToString(ec.SystemInfo.Domainname[:])

	be := New(ec.Buf.Data[:], ec.Buf.NumFields)
	args, err := be.GetArgs(ec.Context.Syscall)
	if err != nil {
		return map[string]any{}, err
	}

	for _, arg := range args {
		event_data[arg.Name] = arg.Value
	}

	return event_data, nil
}

func (e *Event) GetArgs(id int32) ([]Arg, error) {
	var args []Arg

	rawArgs, err := e.GetRawArgs()
	if err != nil {
		return args, err
	}

	for _, rawArg := range rawArgs {
		arg, err := rawArg.GetArg(id)
		if err != nil {
			return []Arg{}, err
		}

		args = append(args, arg)
	}

	return args, nil
}

func (r RawArgInfo) GetArg(id int32) (Arg, error) {
	idx := int(r.Index)

	arg_info, keyExists := syscalls[id]
	if !keyExists || (idx < 0 || idx >= len(arg_info.Args)) {
		sa := SysArg{
			Name:     fmt.Sprintf("arg%d", idx),
			Function: nil,
		}

		arg_info.Args = append(arg_info.Args, sa)

		idx = len(arg_info.Args) - 1
	}

	arg := Arg{}

	switch r.Type {
	case intT:
		val, err := utils.Int(r.Value)
		if err != nil {
			return arg, err
		}
		arg.Value = fmt.Sprintf("%d", val)
	case uintT:
		val, err := utils.Uint(r.Value)
		if err != nil {
			return arg, err
		}

		arg.Value = fmt.Sprintf("%d", val)
	case longT:
		val, err := utils.Int64(r.Value)
		if err != nil {
			return arg, err
		}

		arg.Value = fmt.Sprintf("%d", val)
	case ulongT:
		val, err := utils.Uint64(r.Value)
		if err != nil {
			return arg, err
		}

		arg.Value = fmt.Sprintf("%v", val)
	case strT:
		arg.Value = utils.ToString(r.Value)
	case strArrT:
		arg.Value = "function under development"
	}

	var err error
	arg, err = arg_info.Args[idx].ParseArg(arg.Value)
	if err != nil {
		return Arg{}, err
	}

	return arg, nil
}

func (e *Event) GetRawArgs() ([]RawArgInfo, error) {
	var args []RawArgInfo

	for i := uint8(0); i < e.fieldCount; i++ {
		arg, err := e.GetRawArg()
		if err != nil {
			return []RawArgInfo{}, err
		}
		args = append(args, arg)
	}

	return args, nil
}

func (e *Event) GetRawArg() (RawArgInfo, error) {
	var arg RawArgInfo

	arg.Index = e.buffer[e.cursor]
	e.cursor++
	arg.Type = e.buffer[e.cursor]
	e.cursor++

	switch arg.Type {
	case intT, uintT:
		arg.Size = 4
		arg.Value = e.buffer[e.cursor : e.cursor+arg.Size]
		e.cursor += 4
	case longT, ulongT:
		arg.Size = 8
		arg.Value = e.buffer[e.cursor : e.cursor+arg.Size]
		e.cursor += 8
	case strT:
		sz, err := utils.Uint16(e.buffer[e.cursor : e.cursor+2])
		if err != nil {
			return arg, err
		}
		arg.Size = int(sz)
		e.cursor += 2
		arg.Value = e.buffer[e.cursor : e.cursor+arg.Size]
		e.cursor += arg.Size
	case strArrT:
		arg.Size = 8
		arg.Value = []byte{}
	}

	return arg, nil
}
