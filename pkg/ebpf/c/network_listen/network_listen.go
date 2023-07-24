// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian
package network_listen

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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -target $CURR_ARCH  -type event_data listen listen.bpf.c -- -I../../../../headers
// GetEbpfObject returns the bpf object. This is a wrapper around loadListenObjects
func getEbpfObject() (*listenObjects, error) {
	var bpfObj listenObjects
	err := loadListenObjects(&bpfObj, nil)
	// Returns nil err if any error occurs.
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}

// ListenEventData is the exported data from the eBPF struct counterpart
// The intention is to use the proper Go string instead of byte arrays from C.
// It makes it simpler to use and can generate proper json.
type ListenEventData struct {
	Args [3]uint64
}

// newListenEventDataFromEbpf converts a listen event to a struct. 
// 
// @param e - the event to convert to a struct which can be passed to EventProcessor
func newListenEventDataFromEbpf(e listenEventData) *ListenEventData {
	evt := &ListenEventData{
		Args: [3]uint64{
			e.Args[0],
			e.Args[1],
			e.Args[2],
		},
	}
	return evt
}

type NetworkListenDetector struct {
	ebpfLink   link.Link
	perfReader *perf.Reader
}

// NewNetworkListenDetector creates a new instance of network listen detector. 
func NewNetworkListenDetector() *NetworkListenDetector {
	return &NetworkListenDetector{}
}

// Start the NetworkListenDetector. If it cannot be started an error is returned. This is a blocking call
// 
// @param o - The Listener to start.
// 
// @return Error or nil if everything went fine or no listeners were found for the network. Note that Start does not return an error
func (o *NetworkListenDetector) Start() error {
	bpfObjs, err := getEbpfObject()
	// Returns the error if any.
	if err != nil {
		return err
	}

	l, err := link.Kprobe("__x64_sys_listen", bpfObjs.KprobeListen, nil)
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

// Close closes the NetworkListenDetector. It is safe to call more than once. If Close is called multiple times the first will be returned.
// 
// @param o - The object to close. Must not be nil.
// 
// @return An error if any occurred during closing or nil if no error occurred during closing. This may be non nil in the case of an error
func (o *NetworkListenDetector) Close() error {
	err := o.ebpfLink.Close()
	// Returns the error if any.
	if err != nil {
		return err
	}

	return o.perfReader.Close()
}

// Read reads and returns the next EBPF event from the network.
// 
// @param o - The NetworkListenDetector to read from. 
func (o *NetworkListenDetector) Read() (*ListenEventData, error) {
	var ebpfEvent listenEventData
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

	exportedEvent := newListenEventDataFromEbpf(ebpfEvent)
	return exportedEvent, nil
}

// ReadAsInterface implements Interface. ReadAsInterface by returning the Read method of NetworkListenDetector. This is useful for tests
// 
// @param o
func (o *NetworkListenDetector) ReadAsInterface() (any, error) {
	return o.Read()
}

// Prints information about the listen event to the screen. This is called by the event handler when it receives a Listen_Event_Read event
// 
// @param e - Event data that was received
func printToScreen(e listenEventData) {
	fmt.Println("-----------------------------------------")
	fmt.Printf("Listen_File_descriptor: %d\n", e.Args[0])
	fmt.Printf("Listen_backlog : %d\n", (e.Args[1]))

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
