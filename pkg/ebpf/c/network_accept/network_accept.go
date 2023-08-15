// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian
package network_accept

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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -target $CURR_ARCH  -type event_data accept accept.bpf.c -- -I../../../../headers

// getEbpfObject loads the eBPF objects from the compiled code and returns a pointer to the acceptObjects structure.
const (
    AF_INET  = 2   // Adjust with your actual values
    AF_INET6 = 10
    AF_UNIX  = 1
)
func getEbpfObject() (*acceptObjects, error) {
	var bpfObj acceptObjects
	// Load eBPF objects from the compiled  code into bpfObj.
	err := loadAcceptObjects(&bpfObj, nil)
	// Return any error that occurs during loading.
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}

// AcceptEventData represents the data received from the eBPF program.
// AcceptEventData is the exported data from the eBPF struct counterpart
// The intention is to use the proper Go string instead of byte arrays from C.
// It makes it simpler to use and can generate proper json.
type AcceptEventData struct {
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
}

// newAcceptEventDataFromEbpf converts an EBPF accept event to an AcceptEventData. 
//This is used to avoid having to copy the event data to a new EventData struct and to ensure that it is safe to modify the fields of the EventData struct before passing it to the event handler.
// @param e - the EBPF accept event to convert to an Accept
func newAcceptEventDataFromEbpf(e acceptEventData) *AcceptEventData {
	evt := &AcceptEventData{
			Pid:       e.Pid,
			Tgid:      e.Tgid,
			Uid:       e.Uid,
			Gid:       e.Gid,
			Fd:        e.Fd,
			Port:      e.Port,		
			SaFamily:  e.SaFamily,
			V4Addr:    e.V4Addr,
			V6Addr:    e.V6Addr,
			UnixAddr:  e.UnixAddr,
		}
	return evt
}

// NetworkAcceptDetector represents the detector for network accept events using eBPF.
// NetworkAcceptDetector is a structure to manage eBPF interaction
type NetworkAcceptDetector struct {
	ebpfLink   link.Link
	ringbufReader *ringbuf.Reader
}

// NewNetworkAcceptDetector creates a new instance of NetworkAcceptDetector.
func NewNetworkAcceptDetector() *NetworkAcceptDetector {
	return &NetworkAcceptDetector{}
}

// Start initializes the NetworkAcceptDetector and starts monitoring network accept events.
func (o *NetworkAcceptDetector) Start() error {
	// Load eBPF objects from the compiled  code.
	bpfObjs, err := getEbpfObject()
	// Return any error that occurs during loading.
	if err != nil {
		return err
	}

	// Attach a kprobe to the function "__x64_sys_accept" with the provided eBPF object.
	l, err := link.Kprobe("__x64_sys_accept", bpfObjs.KprobeAccept, nil)
	// Return any error that occurs during creating the Kprobe link.
	if err != nil {
		return err
	}

	o.ebpfLink = l

	// Create a rngbuff reader for the eBPF event.
	rd, err := ringbuf.NewReader(bpfObjs.Event)
	// Return any error that occurs during creating the event reader.
	if err != nil {
		return err
	}

	o.ringbufReader = rd
	return nil
}

// Close stops the NetworkAcceptDetector and closes associated resources.
func (o *NetworkAcceptDetector) Close() error {
	err := o.ebpfLink.Close()
	// Return any error that occurs during closing the link.
	if err != nil {
		return err
	}

	return o.ringbufReader.Close()
}

// Read retrieves the AcceptEventData from the eBPF program.
func (o *NetworkAcceptDetector) Read() (*AcceptEventData, error) {
	var ebpfEvent acceptEventData
	record, err := o.ringbufReader.Read()
	// Return any error that occurs during reading from the event reader.
	if err != nil {
		// If the reader is closed, return the error as is.
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, err
		}
		return nil, err
	}

	// Read the raw sample from the record using binary.Read.
	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &ebpfEvent); err != nil {
		return nil, err
	}
	exportedEvent := newAcceptEventDataFromEbpf(ebpfEvent)
	return exportedEvent, nil
}

// ReadAsInterface implements the ReadAsInterface method of the ebpf.Exporter interface.
// It calls the Read method internally.
func (o *NetworkAcceptDetector) ReadAsInterface() (any, error) {
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

func (e *AcceptEventData) InterpretPort() uint16 {
 return e.Port
}

func (e *AcceptEventData) InterpretFamilyAndIP() (family string, ip string, port uint16) {
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


