// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian
package network_connect

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -target $CURR_ARCH  -type event_data connect connect.bpf.c -- -I../../../../headers

// getEbpfObject loads the eBPF objects and returns a pointer to the connectObjects structure.
const (
    AF_INET  = 2   
    AF_INET6 = 10
    AF_UNIX  = 1
)

func getEbpfObject() (*connectObjects, error) {
	var bpfObj connectObjects
	err := loadConnectObjects(&bpfObj, nil)
	// Return any error that occurs during loading.
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}

// ConnectEventData represents the data received from the eBPF program.
// ConnectEventData is the exported data from the eBPF struct counterpart
// The intention is to use the proper Go string instead of byte arrays from C.
// It makes it simpler to use and can generate proper json.
type ConnectEventData struct {
	Pid      uint32
	Tgid     uint32
	Uid      uint32
	Gid      uint32
	Fd       int32
	SaFamily uint16
	Port     uint16
	V4Addr   struct{ S_addr uint32 }
	V6Addr   struct{ S6Addr [16]uint8 }
	UnixAddr struct{ Path [108]int8 }
	Padding2 uint32
	Addrlen  int32
}

// newConnectEventDataFromEbpf creates a new ConnectEventData instance from the given eBPF data.
func newConnectEventDataFromEbpf(e connectEventData) *ConnectEventData {
	evt := &ConnectEventData{
		Args: [3]uint64{
			Pid:       e.Pid,
			Tgid:      e.Tgid,
			Uid:       e.Uid,
			Gid:       e.Gid,
			Fd:        e.Fd,
			Addrlen:   e.Addrlen,
			Port:      e.Port,		
			SaFamily:  e.SaFamily,
			V4Addr:    e.V4Addr,
			V6Addr:    e.V6Addr,
			UnixAddr:  e.UnixAddr,
		},
	}
	return evt
}

// NetworkConnectDetector represents the detector for network connect events using eBPF.
type NetworkConnectDetector struct {
	ebpfLink   link.Link
	ringbufReader *ringbuf.Reader
}

// NewNetworkConnectDetector creates a new NetworkConnectDetector instance.
func NewNetworkConnectDetector() *NetworkConnectDetector {
	return &NetworkConnectDetector{}
}

// Start initializes the NetworkConnectDetector and starts monitoring network connect events.
func (o *NetworkConnectDetector) Start() error {
	// Load eBPF objects from the compiled C code.
	bpfObjs, err := getEbpfObject()
	// Return any error that occurs during loading.
	if err != nil {
		return err
	}

	l, err := link.Kprobe("__x64_sys_connect", bpfObjs.KprobeConnect, nil)
	// Return any error that occurs during creating the Kprobe link.
	if err != nil {
		return err
	}

	o.ebpfLink = l
	rd, err := ringbuf.NewReader(bpfObjs.Event)

	// Return any error that occurs during creating the  event reader.
	if err != nil {
		return err
	}

	o.ringbufReader = rd
	return nil
}

// Close stops the NetworkConnectDetector and closes associated resources.
func (o *NetworkConnectDetector) Close() error {
	err := o.ebpfLink.Close()
	// Return any error that occurs during closing the link.
	if err != nil {
		return err
	}

	return o.ringbufReader.Close()
}

// Read retrieves the ConnectEventData from the eBPF program.
func (o *NetworkConnectDetector) Read() (*ConnectEventData, error) {
	var ebpfEvent connectEventData
	record, err := o.ringbufReader.Read()
	// Return any error that occurs during reading from the  event reader.
	if err != nil {
		// If the  reader is closed, return the error as is.
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, err
		}
		return nil, err
	}

	// Read the raw sample from the record using binary.Read.
	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &ebpfEvent); err != nil {
		return nil, err
	}
	exportedEvent := newConnectEventDataFromEbpf(ebpfEvent)
	return exportedEvent, nil
}

// ReadAsInterface implements Interface.
func (o *NetworkConnectDetector) ReadAsInterface() (any, error) {
	return o.Read()
}

// Convert IPv4 address from binary to string.
func ipv4ToString(addr uint32) string {
    return fmt.Sprintf("%d.%d.%d.%d", byte(addr), byte(addr>>8), byte(addr>>16), byte(addr>>24))
}


// Convert IPv6 address from binary to string.
func ipv6ToString(addr [16]uint8) string {
    b := make([]byte, 16)
    for i := 0; i < 4; i++ {
        val := binary.BigEndian.Uint32(addr[i*4 : (i+1)*4])
        binary.BigEndian.PutUint32(b[i*4:], val)
    }
    return net.IP(b).String()
}



func byteArrayToString(b [108]int8) string {
    return strings.TrimRight(string((*[108]byte)(unsafe.Pointer(&b))[:]), "\x00")
}

func (e *ConnectEventData) InterpretPort() uint16 {
 return e.Port
}

func (e *ConnectEventData) InterpretFamilyAndIP() (family string, ip string, port uint16) {
    switch e.SaFamily {
    case AF_INET:
        family = "AF_INET"
        ip = ipv4ToString(e.V4Addr.S_addr)
    case AF_INET6:
        family = "AF_INET6"
        ip = ipv6ToString(e.V6Addr.S6Addr)
    case AF_UNIX:
        family = "AF_UNIX"
		ip = byteArrayToString(e.UnixAddr.Path) // Read the path for UNIX socket.
    default:
        family = "UNKNOWN"
        ip = "N/A"
    }
	port = e.InterpretPort() // Get the port
    return family, ip ,port
}

