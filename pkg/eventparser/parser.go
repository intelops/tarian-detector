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

type RawArgInfo struct {
	Index uint8  // index of field
	Type  uint8  // Type of the field (e.g., "int", "string", "long")
	Size  int    // size of field in bytes
	Value []byte // Actual value of the field as a byte slice
}

type ByteStream struct {
	data     []byte
	position int
	nparams  uint8
}

func NewByteStream(inputData []byte, n uint8) *ByteStream {
	return &ByteStream{
		data:     inputData,
		position: 0,
		nparams:  n,
	}
}

var Events TarianEventMap

func DecodeByte(b []byte) (map[string]any, error) {
	var event_data map[string]any = make(map[string]any)

	var ec TarianMetaData
	err := binary.Read(bytes.NewReader(b[0:504]), binary.LittleEndian, &ec)
	if err != nil {
		return map[string]any{}, err
	}

	event_data["ts"] = ec.MetaData.Ts
	event_data["start_time"] = ec.MetaData.Task.StartTime
	event_data["host_pid"] = ec.MetaData.Task.HostPid
	event_data["host_tgid"] = ec.MetaData.Task.HostTgid
	event_data["host_ppid"] = ec.MetaData.Task.HostPpid
	event_data["pid"] = ec.MetaData.Task.Pid
	event_data["tgid"] = ec.MetaData.Task.Tgid
	event_data["ppid"] = ec.MetaData.Task.Ppid
	event_data["uid"] = ec.MetaData.Task.Uid
	event_data["gid"] = ec.MetaData.Task.Gid
	event_data["cgroup_id"] = ec.MetaData.Task.CgroupId
	event_data["mount_ns_id"] = ec.MetaData.Task.MountNsId
	event_data["pid_ns_id"] = ec.MetaData.Task.PidNsId
	event_data["exec_id"] = ec.MetaData.Task.ExecId
	event_data["parent_exec_id"] = ec.MetaData.Task.ParentExecId
	event_data["comm"] = utils.ToString(ec.MetaData.Task.Comm[:])

	// cwd_idx, err := utils.Uint16(ec.MetaData.Task.Cwd[:2])
	// if err != nil {
	// 	return map[string]any{}, nil
	// }

	// cwd_sz, err := utils.Uint16(ec.MetaData.Task.Cwd[2:4])
	// if err != nil {
	// 	return map[string]any{}, nil
	// }

	event_data["event_id"] = ec.MetaData.Event
	event_data["syscall"] = ec.MetaData.Syscall
	event_data["processor_id"] = ec.MetaData.Processor

	event_data["sysname"] = utils.ToString(ec.SystemInfo.Sysname[:])
	event_data["nodename"] = utils.ToString(ec.SystemInfo.Nodename[:])
	event_data["release"] = utils.ToString(ec.SystemInfo.Release[:])
	event_data["version"] = utils.ToString(ec.SystemInfo.Version[:])
	event_data["machine"] = utils.ToString(ec.SystemInfo.Machine[:])
	event_data["domain_name"] = utils.ToString(ec.SystemInfo.Domainname[:])

	fmt.Println(b[504], b[0:525])
	// be := New(ec.Buf.Data[:], ec.Buf.NumFields)
	// args, err := be.GetArgs(ec.MetaData.Syscall)
	// if err != nil {
	// 	return map[string]any{}, err
	// }

	// for _, arg := range args {
	// 	event_data[arg.Name] = arg.Value
	// }

	return event_data, nil
}

// func (e *Event) GetArgs(event TarianEvent) ([]arg, error) {
// 	var args []arg

// 	rawArgs, err := e.GetRawArgs()
// 	if err != nil {
// 		return args, err
// 	}

// 	for _, rawArg := range rawArgs {
// 		ag, err := rawArg.GetArg(event)
// 		if err != nil {
// 			return []arg{}, err
// 		}

// 		args = append(args, ag)
// 	}

// 	return args, nil
// }

func (r RawArgInfo) GetArg(event TarianEvent) (arg, error) {

	// idx := int(0)

	// arg_info, keyExists := 0, false
	// if !keyExists || (idx < 0 || idx >= len([]uint8{})) {

	// 	idx = 0
	// }

	ag := arg{}

	switch r.Type {
	case intT:
		val, err := utils.Int32(r.Value)
		if err != nil {
			return ag, err
		}
		ag.Value = fmt.Sprintf("%d", val)
	case uintT:
		val, err := utils.Uint32(r.Value)
		if err != nil {
			return ag, err
		}

		ag.Value = fmt.Sprintf("%d", val)
	case longT:
		val, err := utils.Int64(r.Value)
		if err != nil {
			return ag, err
		}

		ag.Value = fmt.Sprintf("%d", val)
	case ulongT:
		val, err := utils.Uint64(r.Value)
		if err != nil {
			return ag, err
		}

		ag.Value = fmt.Sprintf("%v", val)
	case strT:
		ag.Value = utils.ToString(r.Value)
	case strArrT:
		ag.Value = "function under development"
	}

	// var err error
	// ag, err = arg_info.Args[idx].ParseArg(ag.value)
	// if err != nil {
	// 	return arg{}, err
	// }

	return ag, nil
}

// func (e *Event) GetRawArgs() ([]RawArgInfo, error) {
// 	var args []RawArgInfo

// 	for i := uint8(0); i < e.fieldCount; i++ {
// 		arg, err := e.GetRawArg()
// 		if err != nil {
// 			return []RawArgInfo{}, err
// 		}
// 		args = append(args, arg)
// 	}

// 	return args, nil
// }

// func (e *Event) GetRawArg() (RawArgInfo, error) {
// 	var arg RawArgInfo

// 	arg.Index = e.buffer[e.cursor]
// 	e.cursor++
// 	arg.Type = e.buffer[e.cursor]
// 	e.cursor++

// 	switch arg.Type {
// 	case intT, uintT:
// 		arg.Size = 4
// 		arg.Value = e.buffer[e.cursor : e.cursor+arg.Size]
// 		e.cursor += 4
// 	case longT, ulongT:
// 		arg.Size = 8
// 		arg.Value = e.buffer[e.cursor : e.cursor+arg.Size]
// 		e.cursor += 8
// 	case strT:
// 		sz, err := utils.Uint16(e.buffer[e.cursor : e.cursor+2])
// 		if err != nil {
// 			return arg, err
// 		}
// 		arg.Size = int(sz)
// 		e.cursor += 2
// 		arg.Value = e.buffer[e.cursor : e.cursor+arg.Size]
// 		e.cursor += arg.Size
// 	case strArrT:
// 		arg.Size = 8
// 		arg.Value = []byte{}
// 	}

// 	return arg, nil
// }

func ParseByteArray(data []byte) (map[string]any, error) {
	/*
		Assumption of bytes pattern in byte array

		metadata + current_working_directory + params
		sizeof(TarianMetaData)+ variable size + varaible size

	*/
	fmt.Println(len(data))

	eventId, err := getEventId(data)
	if err != nil {
		return nil, err
	}

	event := Events[eventId]

	var metaData TarianMetaData
	lenMetaData := binary.Size(metaData)
	err = binary.Read(bytes.NewReader(data[:lenMetaData]), binary.LittleEndian, &metaData)
	if err != nil {
		return nil, err
	}

	if metaData.MetaData.Syscall != int32(event.syscallId) {
		metaData.MetaData.Syscall = int32(event.syscallId)
	}

	record := toMap(metaData)
	record["event_id"] = event.name

	// fmt.Println(data[lenMetaData : lenMetaData+100])
	bs := NewByteStream(data[lenMetaData:], metaData.MetaData.Nparams)
	// cwd, err := bs.readCwd()
	// if err != nil {
	// 	return nil, err
	// }

	ps, err := bs.parseParams(event)
	if err != nil {
		return nil, err
	}

	// record["cwd"] = cwd
	record["context"] = ps

	return record, nil
}

func (bs *ByteStream) parseParams(event TarianEvent) ([]arg, error) {
	fmt.Println(bs.nparams)
	tParams := event.params
	if len(tParams) <= 0 {
		return nil, fmt.Errorf("Missing params in TarianEvent")
	}

	args := []arg{}

	for i := 0; i < int(bs.nparams); i++ {
		if bs.position >= len(bs.data) {
			break
		}

		ag, err := bs.parseParam(tParams[i])
		if err != nil {
			return nil, err
		}

		args = append(args, ag)
	}

	return args, nil
}

func (bs *ByteStream) parseParam(p Param) (arg, error) {
	var res arg

	switch p.paramType {
	case TDT_U8:
		val, err := utils.Uint8(bs.data[bs.position : bs.position+1])
		if err != nil {
			return res, err
		}

		res.Name = p.name
		res.Value = fmt.Sprintf("%v", val)
		bs.position += 1
	case TDT_U16:
		val, err := utils.Uint16(bs.data[bs.position : bs.position+2])
		if err != nil {
			return res, err
		}

		res.Name = p.name
		res.Value = fmt.Sprintf("%v", val)
		bs.position += 2
	case TDT_U32:
		val, err := utils.Uint32(bs.data[bs.position : bs.position+4])
		if err != nil {
			return res, err
		}

		res.Name = p.name
		res.Value = fmt.Sprintf("%v", val)
		bs.position += 4
	case TDT_U64:
		val, err := utils.Uint64(bs.data[bs.position : bs.position+8])
		if err != nil {
			return res, err
		}

		res.Name = p.name
		res.Value = fmt.Sprintf("%v", val)
		bs.position += 8
	case TDT_S8:
		val, err := utils.Int8(bs.data[bs.position : bs.position+1])
		if err != nil {
			return res, err
		}

		res.Name = p.name
		res.Value = fmt.Sprintf("%v", val)
		bs.position += 1
	case TDT_S16:
		val, err := utils.Int16(bs.data[bs.position : bs.position+2])
		if err != nil {
			return res, err
		}

		res.Name = p.name
		res.Value = fmt.Sprintf("%v", val)
		bs.position += 2
	case TDT_S32:
		val, err := utils.Int32(bs.data[bs.position : bs.position+4])
		if err != nil {
			return res, err
		}

		res.Name = p.name
		res.Value = fmt.Sprintf("%v", val)
		bs.position += 4
	case TDT_S64:
		val, err := utils.Int64(bs.data[bs.position : bs.position+8])
		if err != nil {
			return res, err
		}

		res.Name = p.name
		res.Value = fmt.Sprintf("%v", val)
		bs.position += 8
	case TDT_STR, TDT_STR_ARR:
		slen, err := bs.readShort()
		if err != nil {
			return res, err
		}

		fmt.Println("Arr", slen, p.paramType)
		res.Name = p.name
		res.Value = utils.ToString(bs.data[bs.position : bs.position+int(slen)])
		bs.position += int(slen)
	case TDT_BYTE_ARR:
		slen, err := bs.readShort()
		if err != nil {
			return res, err
		}

		res.Name = p.name
		res.Value = fmt.Sprintf("%v", bs.data[bs.position:bs.position+int(slen)])
		bs.position += int(slen)
	}
	return res, nil
}

func (bs *ByteStream) readShort() (uint16, error) {
	sh, err := utils.Uint16(bs.data[bs.position : bs.position+2])
	if err != nil {
		return 0, err
	}

	bs.position += 2
	return sh, nil
}

func (bs *ByteStream) readCwd() (string, error) {
	cp := Param{
		name:      "cwd",
		paramType: TDT_STR,
	}

	res, err := bs.parseParam(cp)
	if err != nil {
		return "", err
	}

	fmt.Println(res.Value, len(res.Value))

	return res.Value, err
}
func getEventId(data []byte) (int, error) {
	if len(data) < 4 {
		return 0, fmt.Errorf("input data length is %d, expected at least %d", len(data), 4)
	}

	var id int32
	err := binary.Read(bytes.NewReader(data[:4]), binary.LittleEndian, &id)
	if err != nil {
		return 0, fmt.Errorf("failed to read event ID from data: %w", err)
	}

	return int(id), nil
}

func toMap(t TarianMetaData) map[string]any {
	m := make(map[string]any)

	m["event_id"] = t.MetaData.Event
	m["ts"] = t.MetaData.Ts
	m["syscall_id"] = t.MetaData.Syscall
	m["processor"] = t.MetaData.Processor

	// task
	m["start_time"] = t.MetaData.Task.StartTime
	m["host_pid"] = t.MetaData.Task.HostPid
	m["host_tgid"] = t.MetaData.Task.HostTgid
	m["host_ppid"] = t.MetaData.Task.HostPpid
	m["pid"] = t.MetaData.Task.Pid
	m["tgid"] = t.MetaData.Task.Tgid
	m["ppid"] = t.MetaData.Task.Ppid
	m["uid"] = t.MetaData.Task.Uid
	m["gid"] = t.MetaData.Task.Gid
	m["cgroup_id"] = t.MetaData.Task.CgroupId
	m["mount_ns_id"] = t.MetaData.Task.MountNsId
	m["pid_ns_id"] = t.MetaData.Task.PidNsId
	m["exec_id"] = t.MetaData.Task.ExecId
	m["parent_exec_id"] = t.MetaData.Task.ParentExecId
	m["process_name"] = utils.ToString(t.MetaData.Task.Comm[:])
	m["directory"] = utils.ToString(t.MetaData.Task.Cwd[:])

	m["sysname"] = utils.ToString(t.SystemInfo.Sysname[:])
	m["nodename"] = utils.ToString(t.SystemInfo.Nodename[:])
	m["release"] = utils.ToString(t.SystemInfo.Release[:])
	m["version"] = utils.ToString(t.SystemInfo.Version[:])
	m["machine"] = utils.ToString(t.SystemInfo.Machine[:])
	m["domainname"] = utils.ToString(t.SystemInfo.Domainname[:])

	return m
}
