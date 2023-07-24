// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian
package network_connect

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"

	"fmt"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -target $CURR_ARCH  -type event_data connect connect.bpf.c -- -I../../../../headers
// GetEbpfObject returns the bpf object
func getEbpfObject() (*connectObjects, error) {
	var bpfObj connectObjects
	err := loadConnectObjects(&bpfObj, nil)
	// Returns nil err if any error occurs.
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}

// ConnectEventData is the exported data from the eBPF struct counterpart
// The intention is to use the proper Go string instead of byte arrays from C.
// It makes it simpler to use and can generate proper json.
type ConnectEventData struct {
	Args [3]uint64
}

// newConnectEventDataFromEbpf converts a EBPF connect event to a Conn event. This is used to implement event propagation from other event types that don t have a common protocol.
// 
// @param e - the EBPF connect event to convert to a Conn event
func newConnectEventDataFromEbpf(e connectEventData) *ConnectEventData {
	evt := &ConnectEventData{
		Args: [3]uint64{
			e.Args[0],
			e.Args[1],
			e.Args[2],
		},
	}
	return evt
}

type NetworkConnectDetector struct {
	ebpfLink   link.Link
	perfReader *perf.Reader
}

// NewNetworkConnectDetector creates a new instance of the network connect detector. It is safe to call this method multiple times
func NewNetworkConnectDetector() *NetworkConnectDetector {
	return &NetworkConnectDetector{}
}

func (o *NetworkConnectDetector) Start() error {
	bpfObjs, err := getEbpfObject()
	// Returns the error if any.
	if err != nil {
		return err
	}

	l, err := link.Kprobe("__x64_sys_connect", bpfObjs.KprobeConnect, nil)
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

// Close closes the EBPF link and perf reader. It is safe to call multiple times. If an error is returned it is returned as the first error encountered.
// 
// @param o - NetworkConnectDetector to be closed. Must not be nil.
// 
// @return Error returned by Open or any error encountered while closing the EBPF link and perf reader. nil if no error occurred
func (o *NetworkConnectDetector) Close() error {
	err := o.ebpfLink.Close()
	// Returns the error if any.
	if err != nil {
		return err
	}

	return o.perfReader.Close()
}

// Read reads and returns the next ConnectEvent from the EBPF file. 
// 
// @param o
func (o *NetworkConnectDetector) Read() (*ConnectEventData, error) {
	var ebpfEvent connectEventData
	record, err := o.perfReader.Read()
	// Returns the error if any.
	if err != nil {
		// Returns the error if any.
		if errors.Is(err, perf.ErrClosed) {
			return nil, err
		}
		return nil, err
	}

	// Read the raw sample from the record. 
	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &ebpfEvent); err != nil {
		return nil, err
	}

	printToScreen(ebpfEvent)

	exportedEvent := newConnectEventDataFromEbpf(ebpfEvent)
	return exportedEvent, nil
}

// ReadAsInterface implements Interface.
func (o *NetworkConnectDetector) ReadAsInterface() (any, error) {
	return o.Read()
}

>>>>>>>>>>DOCIFY-START - yjqloqrbzpcj >>>>>>>>>>
// Prints information about the connection to screen. 
>>>>>>>>>>DOCIFY-END - yjqloqrbzpcj >>>>>>>>>>
func printToScreen(e connectEventData) {
	fmt.Println("-----------------------------------------")
	fmt.Printf("Connect_File_descriptor: %d\n", e.Args[0])
	fmt.Printf("Connect_Address : %s\n", IPv6(e.Args[1]))
	fmt.Printf("Connect_Address_length: %d\n", e.Args[2])
	fmt.Println("-----------------------------------------")
}

// IP converts an IPv4 address to a string. The format is big endian uint32 in network byte order
// 
// @param in - the IPv4 address to convert
// 
// @return the string representation of the IP address in network byte order e. g. 192. 168. 1
func IP(in uint32) string {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, in)
	return ip.String()
}

// IPv6 converts an uint64 to string. The string is in big endian format. It does not check if the input is valid or not
// 
// @param in - the uint64 to convert to string
// 
// @return the string representation of the uint64 in big endian format or empty string if not valid or not a
func IPv6(in uint64) string {

	ip := make(net.IP, net.IPv6len)
	binary.BigEndian.PutUint64(ip, in)
	return ip.String()
}
