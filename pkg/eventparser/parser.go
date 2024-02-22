// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package eventparser

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/intelops/tarian-detector/pkg/err"
	"github.com/intelops/tarian-detector/pkg/utils"
)

var parserErr = err.New("eventparser.parser")

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

func ParseByteArray(data []byte) (map[string]any, error) {
	/*
		Assuming a specific byte pattern within the byte array:

		tarianmetadata + params
	*/
	eventId, err := getEventId(data)
	if err != nil {
		return nil, parserErr.Throwf("%v", err)
	}

	event, noEvent := Events[eventId]
	if !noEvent {
		return nil, parserErr.Throwf("missing event from 'var Events TarianEventMap' for key: %v", eventId)
	}

	var metaData TarianMetaData
	lenMetaData := binary.Size(metaData)
	err = binary.Read(bytes.NewReader(data[:lenMetaData]), binary.LittleEndian, &metaData)
	if err != nil {
		return nil, parserErr.Throwf("%v", err)
	}

	if metaData.MetaData.Syscall != int32(event.syscallId) {
		metaData.MetaData.Syscall = int32(event.syscallId)
	}

	record := toMap(metaData)
	record["eventId"] = event.name

	bs := NewByteStream(data[lenMetaData:], metaData.MetaData.Nparams)
	ps, err := bs.parseParams(event)
	if err != nil {
		return nil, parserErr.Throwf("%v", err)
	}

	record["context"] = ps

	return record, nil
}

func (bs *ByteStream) parseParams(event TarianEvent) ([]arg, error) {
	tParams := event.params
	if len(tParams) <= 0 {
		return nil, parserErr.Throwf("missing event from 'var Events TarianEventMap'")
	}

	args := make([]arg, 0, bs.nparams)

	for i := 0; i < int(bs.nparams); i++ {
		if bs.position >= len(bs.data) {
			break
		}

		if i >= len(tParams) {
			break
		}

		ag, err := bs.parseParam(tParams[i])
		if err != nil {
			return nil, parserErr.Throwf("%v", err)
		}

		args = append(args, ag)
	}

	return args, nil
}

func (bs *ByteStream) parseParam(p Param) (arg, error) {
	var pVal any
	var err error

	switch p.paramType {
	case TDT_U8:
		pVal, err = bs.parseUint8()
	case TDT_U16:
		pVal, err = bs.parseUint16()
	case TDT_U32:
		pVal, err = bs.parseUint32()
	case TDT_U64:
		pVal, err = bs.parseUint64()
	case TDT_S8:
		pVal, err = bs.parseInt8()
	case TDT_S16:
		pVal, err = bs.parseInt16()
	case TDT_S32:
		pVal, err = bs.parseInt32()
	case TDT_S64:
		pVal, err = bs.parseInt64()
	case TDT_STR, TDT_STR_ARR:
		pVal, err = bs.parseString()
	case TDT_BYTE_ARR:
		pVal, err = bs.parseRawArray()
	case TDT_SOCKADDR:
		pVal, err = bs.parseSocketAddress()
	}

	if err != nil {
		return arg{}, parserErr.Throwf("%v", err)
	}

	return p.processValue(pVal)
}

func (bs *ByteStream) parseUint8() (uint8, error) {
	val, err := utils.Uint8(bs.data, bs.position)
	bs.position += 1

	return val, err
}

func (bs *ByteStream) parseUint16() (uint16, error) {
	val, err := utils.Uint16(bs.data, bs.position)
	bs.position += 2

	return val, err
}

func (bs *ByteStream) parseUint32() (uint32, error) {
	val, err := utils.Uint32(bs.data, bs.position)
	bs.position += 4

	return val, err
}

func (bs *ByteStream) parseUint64() (uint64, error) {
	val, err := utils.Uint64(bs.data, bs.position)
	bs.position += 8

	return val, err
}

func (bs *ByteStream) parseInt8() (int8, error) {
	val, err := utils.Int8(bs.data, bs.position)
	bs.position += 1

	return val, err
}

func (bs *ByteStream) parseInt16() (int16, error) {
	val, err := utils.Int16(bs.data, bs.position)
	bs.position += 2

	return val, err
}

func (bs *ByteStream) parseInt32() (int32, error) {
	val, err := utils.Int32(bs.data, bs.position)
	bs.position += 4

	return val, err
}

func (bs *ByteStream) parseInt64() (int64, error) {
	val, err := utils.Int64(bs.data, bs.position)
	bs.position += 8

	return val, err
}

func (bs *ByteStream) parseIpv4() string {
	val := utils.Ipv4(bs.data, bs.position)
	bs.position += 4

	return val
}

func (bs *ByteStream) parseIpv6() string {
	val := utils.Ipv6(bs.data, bs.position)
	bs.position += 16

	return val
}

func (bs *ByteStream) parseString() (string, error) {
	slen, err := bs.parseUint16()
	if err != nil {
		return "", parserErr.Throwf("%v", err)
	}

	val := utils.ToString(bs.data, bs.position, int(slen))
	bs.position += int(slen)

	return val, nil
}

func (bs *ByteStream) parseRawArray() ([]byte, error) {
	slen, err := bs.parseUint16()
	if err != nil {
		return []byte{}, parserErr.Throwf("%v", err)
	}

	val := bs.data[bs.position : bs.position+int(slen)]
	bs.position += int(slen)

	return val, nil
}

func (bs *ByteStream) parseSocketAddress() (any, error) {
	family, err := bs.parseUint8()
	if err != nil {
		return nil, parserErr.Throwf("%v", err)
	}

	switch family {
	case AF_INET:
		{
			type sockaddr_in struct {
				Family  string
				Sa_addr string
				Sa_port uint16
			}

			var addr sockaddr_in
			addr.Family = "AF_INET"

			addr.Sa_addr = bs.parseIpv4()

			port, err := bs.parseUint16()
			if err != nil {
				return nil, parserErr.Throwf("%v", err)
			}

			addr.Sa_port = utils.Ntohs(port)

			return fmt.Sprintf("%+v", addr), nil
		}
	case AF_INET6:
		{
			type sockaddr_in6 struct {
				Family  string
				Sa_addr string
				Sa_port uint16
			}

			var addr sockaddr_in6
			addr.Family = "AF_INET6"

			addr.Sa_addr = bs.parseIpv6()

			port, err := bs.parseUint16()
			if err != nil {
				return nil, parserErr.Throwf("%v", err)
			}

			addr.Sa_port = utils.Ntohs(port)

			return fmt.Sprintf("%+v", addr), nil
		}
	case AF_UNIX:
		{
			type sockaddr_un struct {
				Family   string
				Sun_path string
			}

			var addr sockaddr_un
			addr.Family = "AF_UNIX"

			val, err := bs.parseString()
			if err != nil {
				return nil, parserErr.Throwf("%v", err)
			}

			addr.Sun_path = val

			return fmt.Sprintf("%+v", addr), nil
		}
	default:
		return nil, nil
	}
}

func getEventId(data []byte) (int, error) {
	if len(data) < 4 {
		return 0, parserErr.Throwf("input data length is %d, expected to be at least %d", len(data), 4)
	}

	id, err := utils.Int32(data, 0)
	if err != nil {
		return 0, parserErr.Throwf("failed to read eventId from data: %v", err)
	}

	return int(id), nil
}

func toMap(t TarianMetaData) map[string]any {
	m := make(map[string]any)

	m["timestamp"] = t.MetaData.Ts
	m["syscallId"] = t.MetaData.Syscall
	m["processor"] = t.MetaData.Processor

	// task
	m["threadStartTime"] = t.MetaData.Task.StartTime
	m["hostProcessId"] = t.MetaData.Task.HostPid
	m["hostThreadId"] = t.MetaData.Task.HostTgid
	m["hostParentProcessId"] = t.MetaData.Task.HostPpid
	m["processId"] = t.MetaData.Task.Pid
	m["threadId"] = t.MetaData.Task.Tgid
	m["parentProcessId"] = t.MetaData.Task.Ppid
	m["userId"] = t.MetaData.Task.Uid
	m["groupId"] = t.MetaData.Task.Gid
	m["cgroupId"] = t.MetaData.Task.CgroupId
	m["mountNamespace"] = t.MetaData.Task.MountNsId
	m["pidNamespace"] = t.MetaData.Task.PidNsId
	m["execId"] = t.MetaData.Task.ExecId
	m["parentExecId"] = t.MetaData.Task.ParentExecId
	m["processName"] = utils.ToString(t.MetaData.Task.Comm[:], 0, len(t.MetaData.Task.Comm))
	m["directory"] = utils.ToString(t.MetaData.Task.Cwd[:], 0, len(t.MetaData.Task.Cwd))

	m["sysname"] = utils.ToString(t.SystemInfo.Sysname[:], 0, len(t.SystemInfo.Sysname))
	m["nodename"] = utils.ToString(t.SystemInfo.Nodename[:], 0, len(t.SystemInfo.Nodename))
	m["release"] = utils.ToString(t.SystemInfo.Release[:], 0, len(t.SystemInfo.Release))
	m["version"] = utils.ToString(t.SystemInfo.Version[:], 0, len(t.SystemInfo.Version))
	m["machine"] = utils.ToString(t.SystemInfo.Machine[:], 0, len(t.SystemInfo.Machine))
	m["domainname"] = utils.ToString(t.SystemInfo.Domainname[:], 0, len(t.SystemInfo.Domainname))

	return m
}
