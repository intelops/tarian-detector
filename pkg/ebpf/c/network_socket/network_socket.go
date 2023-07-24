// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian
package network_socket

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -target $CURR_ARCH  -type event_data socket socket.bpf.c -- -I../../../../headers

// Returns EBPF object. This is a wrapper around loadSocketObjects to avoid having to create a bpf object
func getEbpfObject() (*socketObjects, error) {
	var bpfObj socketObjects
	err := loadSocketObjects(&bpfObj, nil)
	// Returns nil err if any error occurs.
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}

// EntryEventData is the exported data from the eBPF struct counterpart
// The intention is to use the proper Go string instead of byte arrays from C.
// It makes it simpler to use and can generate proper json.
type SocketEventData struct {
	Domain   uint32
	Type     uint32
	Protocol int32
}

// newSocketEventDataFromEbpf creates a new SocketEventData from an EventBPF event. This is used to implement event propagation.
// 
// @param e - the event to convert to a SocketEventData.
func newSocketEventDataFromEbpf(e socketEventData) *SocketEventData {
	evt := &SocketEventData{
		Domain:   e.Domain,
		Type:     e.Type,
		Protocol: e.Protocol,
	}
	return evt
}

type NetworkSocketDetector struct {
	ebpfLink   link.Link
	perfReader *perf.Reader
}

// NewNetworkSocketDetector creates a new instance of network socket detector. 
func NewNetworkSocketDetector() *NetworkSocketDetector {
	return &NetworkSocketDetector{}
}

// Start detects network sockets. The caller must call Stop when finished with the detector. If Start returns an error NetworkSocketDetector will not be able to detect the socket and it will return that error.
// 
// @param o - An instance of NetworkSocketDetector. This is required for use as a Start function.
// 
// @return A non nil error if any error occurs during initialization or initialization. Otherwise nil is returned to indicate success
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
	rd, err := perf.NewReader(bpfObjs.Event, os.Getpagesize())

	// Returns the error if any.
	if err != nil {
		return err
	}

	o.perfReader = rd
	return nil
}

// Close closes the NetworkSocketDetector. If it is already closed it does nothing. 
// 
// @param o - The object to close.
// 
// @return An error if any occurred during closing or nil if everything was fine to close the detector. 
func (o *NetworkSocketDetector) Close() error {
	err := o.ebpfLink.Close()
	// Returns the error if any.
	if err != nil {
		return err
	}

	return o.perfReader.Close()
}

// Read reads a socket event from the perf reader and converts it to SocketEventData. This is a blocking function and should be called in a goroutine
// 
// @param o
func (o *NetworkSocketDetector) Read() (*SocketEventData, error) {
	var ebpfEvent socketEventData
	record, err := o.perfReader.Read()
	// Returns the error if any.
	if err != nil {
		// Returns the error if any.
		if errors.Is(err, perf.ErrClosed) {
			return nil, err
		}
		return nil, err
	}

	// Read the raw sample from the record. RawSample
	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &ebpfEvent); err != nil {
		return nil, err
	}

	printToScreen(ebpfEvent)

	exportedEvent := newSocketEventDataFromEbpf(ebpfEvent)
	return exportedEvent, nil
}

func (o *NetworkSocketDetector) ReadAsInterface() (any, error) {
	return o.Read()
}

// Prints to screen the event. This is a debugging function to be used in conjunction with printSocketEvents
// 
// @param e - the event to print
func printToScreen(e socketEventData) {
	fmt.Println("-----------------------------------------")
	fmt.Printf("Domain: %s\n", Domain(e.Domain))
	fmt.Printf("Type : %s\n", Type(e.Type))
	fmt.Printf("Protocol: %s\n", Protocol(e.Protocol))
	fmt.Println("-----------------------------------------")
}

// Prints a message to the user. This is a convenience function for prompting the user to enter a message.
// 
// @param msg - The message to print to the user before exiting
func prompt(msg string) {
	fmt.Printf("\n%s \r", msg)
}

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

// getSocketDomain Function
// Domain returns the name of the socket domain. This is used to distinguish between Unix domain names and Unix domain names that are stored in socket.
// 
// @param sd - The socket domain to lookup.
// 
// @return The name of the socket domain or the value of sd if it is not found in the map of socket
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

var socketTypes = map[uint32]string{
	1:  "SOCK_STREAM",
	2:  "SOCK_DGRAM",
	3:  "SOCK_RAW",
	4:  "SOCK_RDM",
	5:  "SOCK_SEQPACKET",
	6:  "SOCK_DCCP",
	10: "SOCK_PACKET",
}

// Type returns the string representation of the socket type. See socktype. go for details. This is a portable implementation of the socket. Type function.
// 
// @param st - The socket type to convert. This must be a bitmask of the same length as the number of bits in the socket type.
// 
// @return The string representation of the socket type as described in RFC 1918 section 2. 2. 1.
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

var protocols = map[int32]string{
	1:  "ICMP",
	6:  "TCP",
	17: "UDP",
	58: "ICMPv6",
}

// getProtocol Function
// Protocol returns the name of the protocol. e
// 
// @param proto - the protocol to look up
// 
// @return the name of the protocol 
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
