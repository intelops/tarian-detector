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

// TarianEventMap represents a map of Tarian events
var Events TarianEventMap

// ByteStream represents a stream of bytes.
type ByteStream struct {
	data     []byte // data is the array of bytes in the stream
	position int    // position is the current position in the stream
	nparams  uint8  // nparams is the number of parameters
}

// NewByteStream creates a new ByteStream with the given input data and n parameters.
func NewByteStream(inputData []byte, n uint8) *ByteStream {
	return &ByteStream{
		data:     inputData,
		position: 0,
		nparams:  n,
	}
}

// ParseByteArray takes a byte array as input and returns a map[string]any and an error.
// It first retrieves the eventId from the input data, then checks if the event exists in the Events map.
// It then reads the TarianMetaData from the data, updates the Syscall if needed, and parses the parameters.
// Finally, it returns the parsed record and any error encountered during parsing.
func ParseByteArray(data []byte) (map[string]any, error) {
	// Assuming a specific byte pattern within the byte array:
	// tarianmetadata + params

	eventId, err := getEventId(data)
	if err != nil {
		return nil, parserErr.Throwf("%v", err)
	}

	event, noEvent := Events[TarianEventsE(eventId)]
	if !noEvent {
		return nil, parserErr.Throwf("missing event from 'var Events TarianEventMap' for key: %v", eventId)
	}

	var metaData TarianMetaData
	lenMetaData := binary.Size(metaData)
	err = binary.Read(bytes.NewReader(data), binary.LittleEndian, &metaData)
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

// parseParams parses the parameters of a TarianEvent from the ByteStream
func (bs *ByteStream) parseParams(event TarianEvent) ([]Arg, error) {
	tParams := event.params
	if len(tParams) <= 0 {
		return nil, parserErr.Throwf("missing event from 'var Events TarianEventMap'")
	}

	args := make([]Arg, 0, bs.nparams)

	for i := 0; i < int(bs.nparams); i++ {
		// parseParams parses the parameters of a TarianEvent from the ByteStream
		if bs.position >= len(bs.data) {
			break
		}

		// Check if the index is out of range for tParams
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

// parseParam parses the given parameter based on its type and returns the parsed value.
func (bs *ByteStream) parseParam(p Param) (Arg, error) {
	var pVal any
	var err error

	// Switch based on the parameter type
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
		return Arg{}, parserErr.Throwf("%v", err)
	}

	return p.processValue(pVal)
}

// parseUint8 reads an 8-bit unsigned integer from the ByteStream and returns it.
// It also increments the position by 1.
func (bs *ByteStream) parseUint8() (uint8, error) {
	val, err := utils.Uint8(bs.data, bs.position)
	bs.position += 1

	return val, err
}

// parseUint16 reads a 16-bit unsigned integer from the ByteStream and returns it.
// It also increments the position by 2.
func (bs *ByteStream) parseUint16() (uint16, error) {
	val, err := utils.Uint16(bs.data, bs.position)
	bs.position += 2

	return val, err
}

// parseUint32 reads a 32-bit unsigned integer from the ByteStream and returns it.
// It also increments the position by 4.
func (bs *ByteStream) parseUint32() (uint32, error) {
	val, err := utils.Uint32(bs.data, bs.position)
	bs.position += 4

	return val, err
}

// parseUint64 reads a 64-bit unsigned integer from the ByteStream and returns it.
// It also increments the position by 8.
func (bs *ByteStream) parseUint64() (uint64, error) {
	val, err := utils.Uint64(bs.data, bs.position)
	bs.position += 8

	return val, err
}

// parseInt8 reads an 8-bit signed integer from the ByteStream and returns it.
// It also increments the position by 1.
func (bs *ByteStream) parseInt8() (int8, error) {
	val, err := utils.Int8(bs.data, bs.position)
	bs.position += 1

	return val, err
}

// parseInt16 reads a 16-bit signed integer from the ByteStream and returns it.
// It also increments the position by 2.
func (bs *ByteStream) parseInt16() (int16, error) {
	val, err := utils.Int16(bs.data, bs.position)
	bs.position += 2

	return val, err
}

// parseInt32 reads a 32-bit signed integer from the ByteStream and returns it.
// It also increments the position by 4.
func (bs *ByteStream) parseInt32() (int32, error) {
	val, err := utils.Int32(bs.data, bs.position)
	bs.position += 4

	return val, err
}

// parseInt64 reads a 64-bit signed integer from the ByteStream and returns it.
// It also increments the position by 8.
func (bs *ByteStream) parseInt64() (int64, error) {
	val, err := utils.Int64(bs.data, bs.position)
	bs.position += 8

	return val, err
}

// parseIpv4 reads a 32-bit IPv4 address from the ByteStream and returns it.
// It also increments the position by 4.
func (bs *ByteStream) parseIpv4() string {
	val := utils.Ipv4(bs.data, bs.position)
	bs.position += 4

	return val
}

// parseIpv6 reads a 128-bit IPv6 address from the ByteStream and returns it.
// It also increments the position by 16.
func (bs *ByteStream) parseIpv6() string {
	val := utils.Ipv6(bs.data, bs.position)
	bs.position += 16

	return val
}

// parseString reads a string from the ByteStream and returns it.
// It also increments the position by the length of the string.
func (bs *ByteStream) parseString() (string, error) {
	slen, err := bs.parseUint16()
	if err != nil {
		return "", parserErr.Throwf("%v", err)
	}

	val := utils.ToString(bs.data, bs.position, int(slen))
	bs.position += int(slen)

	return val, nil
}

// parseRawArray reads a raw array from the ByteStream and returns it.
// It also increments the position by the length of the array.
func (bs *ByteStream) parseRawArray() ([]byte, error) {
	slen, err := bs.parseUint16()
	if err != nil {
		return []byte{}, parserErr.Throwf("%v", err)
	}

	val := bs.data[bs.position : bs.position+int(slen)]
	bs.position += int(slen)

	return val, nil
}

// parseSocketAddress reads a socket address from the ByteStream and returns it.
// It also increments the position by the length of the socket address.
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

// getEventId reads the eventId from the data and returns it as an int.
func getEventId(data []byte) (int, error) {
	id, err := utils.Int32(data, 0)
	if err != nil {
		return 0, parserErr.Throwf("failed to read eventId from data: %v", err)
	}

	return int(id), nil
}

// toMap converts the TarianMetaData struct to a map[string]any.
func toMap(t TarianMetaData) map[string]any {
	m := make(map[string]any)

	m["timestamp"] = t.MetaData.Ts
	m["syscallId"] = t.MetaData.Syscall
	m["processor"] = t.MetaData.Processor

	// task fields
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

	// SystemInfo fields
	m["sysname"] = utils.ToString(t.SystemInfo.Sysname[:], 0, len(t.SystemInfo.Sysname))
	m["nodename"] = utils.ToString(t.SystemInfo.Nodename[:], 0, len(t.SystemInfo.Nodename))
	m["release"] = utils.ToString(t.SystemInfo.Release[:], 0, len(t.SystemInfo.Release))
	m["version"] = utils.ToString(t.SystemInfo.Version[:], 0, len(t.SystemInfo.Version))
	m["machine"] = utils.ToString(t.SystemInfo.Machine[:], 0, len(t.SystemInfo.Machine))
	m["domainname"] = utils.ToString(t.SystemInfo.Domainname[:], 0, len(t.SystemInfo.Domainname))

	return m
}
