// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian
package network_socket

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -target $CURR_ARCH  -type event_data socket socket.bpf.c -- -I../../../../headers

// getEbpfObject returns the eBPF object. It loads the eBPF objects from the compiled code into a Go struct.
func getEbpfObject() (*socketObjects, error) {
	var bpfObj socketObjects
	err := loadSocketObjects(&bpfObj, nil)
	// Returns nil err if any error occurs.
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}

// SocketEventData is the exported data from the eBPF struct counterpart.
// The intention is to use the proper Go string instead of byte arrays from C.
// It makes it simpler to use and can generate proper JSON.
type SocketEventData struct {
	Pid      uint32
	Tgid     uint32
	Uid      uint32
	Gid      uint32
	Domain   uint32
	Type     uint32
	Protocol uint32
}

// newSocketEventDataFromEbpf creates a new SocketEventData from an EventBPF event. This is used to implement event propagation.
func newSocketEventDataFromEbpf(e socketEventData) *SocketEventData {
	evt := &SocketEventData{
		Pid:   		e.Pid,
		Tgid:   	e.Tgid,
		Uid:   		e.Uid,
		Gid:   		e.Gid,
		Domain:   	e.Domain,
		Type:     	e.Type,
		Protocol: 	e.Protocol,
	}
	return evt
}

// NetworkSocketDetector represents the network socket detector.
type NetworkSocketDetector struct {
	ebpfLink   link.Link
	ringbufReader *ringbuf.Reader
}

// NewNetworkSocketDetector creates a new instance of network socket detector. 
func NewNetworkSocketDetector() *NetworkSocketDetector {
	return &NetworkSocketDetector{}
}

// Start starts the network socket detector by attaching the eBPF program to the kprobe for the "__x64_sys_socket" function.
func (o *NetworkSocketDetector) Start() error {
	bpfObjs, err := getEbpfObject()
	// Returns the error if any.
	if err != nil {
		return err
	}

	l, err := link.Kprobe("__x64_sys_socket", bpfObjs.KprobeSocket, nil)
	// Returns the error if any.
	if err != nil {
		return err
	}

	o.ebpfLink = l
	rd, err := ringbuf.NewReader(bpfObjs.Event)

	// Returns the error if any.
	if err != nil {
		return err
	}

	o.ringbufReader = rd
	return nil
}

// Close closes the network socket detector.
func (o *NetworkSocketDetector) Close() error {
	err := o.ebpfLink.Close()
	// Returns the error if any.
	if err != nil {
		return err
	}

	return o.ringbufReader.Close()
}

// Read reads the captured socket event data.
func (o *NetworkSocketDetector) Read() (*SocketEventData, error) {
	var ebpfEvent socketEventData
	record, err := o.ringbufReader.Read()
	// Returns the error if any.
	if err != nil {
		// Returns the error if any.
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, err
		}
		return nil, err
	}

	// Read the raw sample from the record.
	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &ebpfEvent); err != nil {
		return nil, err
	}

	exportedEvent := newSocketEventDataFromEbpf(ebpfEvent)
	return exportedEvent, nil
}

// ReadAsInterface reads the captured socket event data as an interface.
func (o *NetworkSocketDetector) ReadAsInterface() (any, error) {
	return o.Read()
}

// socketDomains contains the mapping of socket domain values to their names.
var socketDomains = map[uint32]string{
	0:  "AF_UNSPEC",
	1:  "AF_UNIX",
	2:  "AF_INET",
	3:  "AF_AX25",
	4:  "AF_IPX",
	5:  "AF_APPLETALK",
	6:  "AF_NETROM",
	7:  "AF_BRIDGE",
	8:  "AF_ATMPVC",
	9:  "AF_X25",
	10: "AF_INET6",
	11: "AF_ROSE",
	12: "AF_DECnet",
	13: "AF_NETBEUI",
	14: "AF_SECURITY",
	15: "AF_KEY",
	16: "AF_NETLINK",
	17: "AF_PACKET",
	18: "AF_ASH",
	19: "AF_ECONET",
	20: "AF_ATMSVC",
	21: "AF_RDS",
	22: "AF_SNA",
	23: "AF_IRDA",
	24: "AF_PPPOX",
	25: "AF_WANPIPE",
	26: "AF_LLC",
	27: "AF_IB",
	28: "AF_MPLS",
	29: "AF_CAN",
	30: "AF_TIPC",
	31: "AF_BLUETOOTH",
	32: "AF_IUCV",
	33: "AF_RXRPC",
	34: "AF_ISDN",
	35: "AF_PHONET",
	36: "AF_IEEE802154",
	37: "AF_CAIF",
	38: "AF_ALG",
	39: "AF_NFC",
	40: "AF_VSOCK",
	41: "AF_KCM",
	42: "AF_QIPCRTR",
	43: "AF_SMC",
	44: "AF_XDP",
}

// Domain returns the name of the socket domain based on the given value.
// 
// @param sd - The socket domain to lookup.
// 
// @return The name of the socket domain or the value of sd if it is not found in the map.
func Domain(sd uint32) string {
	// readSocketDomain prints the `domain` bitmask argument of the `socket` syscall
	// http://man7.org/linux/man-pages/man2/socket.2.html

	var res string

	if sdName, ok := socketDomains[sd]; ok {
		res = sdName
	} else {
		res = strconv.Itoa(int(sd))
	}

	return res
}

// socketTypes contains the mapping of socket type values to their names.
var socketTypes = map[uint32]string{
	1:  "SOCK_STREAM",
	2:  "SOCK_DGRAM",
	3:  "SOCK_RAW",
	4:  "SOCK_RDM",
	5:  "SOCK_SEQPACKET",
	6:  "SOCK_DCCP",
	10: "SOCK_PACKET",
}

// Type returns the string representation of the socket type based on the given bitmask.
// 
// @param st - The socket type to convert.
// 
// @return The string representation of the socket type.
func Type(st uint32) string {
	// readSocketType prints the `type` bitmask argument of the `socket` syscall
	// http://man7.org/linux/man-pages/man2/socket.2.html
	// https://elixir.bootlin.com/linux/v5.5.3/source/arch/mips/include/asm/socket.h

	var f []string

	
	if stName, ok := socketTypes[st&0xf]; ok {
		f = append(f, stName)
	} else {
		f = append(f, strconv.Itoa(int(st)))
	}
	if st&000004000 == 000004000 {
		f = append(f, "SOCK_NONBLOCK")
	}
	if st&002000000 == 002000000 {
		f = append(f, "SOCK_CLOEXEC")
	}

	return strings.Join(f, "|")
}

// protocols contains the mapping of protocol values to their names.
var protocols = map[int32]string{
	1:  "ICMP",
	6:  "TCP",
	17: "UDP",
	58: "ICMPv6",
}

// Protocol returns the name of the protocol based on the given value.
// 
// @param proto - The protocol to look up.
// 
// @return The name of the protocol. 
func Protocol(proto int32) string {
	var res string

	// get the protocol name or return the protocol name
	if protoName, ok := protocols[proto]; ok {
		res = protoName
	} else {
		res = strconv.Itoa(int(proto))
	}

	return res
}
