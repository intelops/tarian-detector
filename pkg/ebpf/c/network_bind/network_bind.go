// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian
package network_bind

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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -target $CURR_ARCH  -type event_data bind bind.bpf.c -- -I../../../../headers
// GetEbpfObject returns the BPF object
func getEbpfObject() (*bindObjects, error) {
	var bpfObj bindObjects
	err := loadBindObjects(&bpfObj, nil)
	// Returns nil err if any error occurs.
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}

// BindEventData is the exported data from the eBPF struct counterpart
// The intention is to use the proper Go string instead of byte arrays from C.
// It makes it simpler to use and can generate proper json.
type BindEventData struct {
	Args [3]uint64
}

// newBindEventDataFromEbpf converts an EBPF event to a BIND event. This is used to create a copy of the event that can be sent to the network without copying it into the event buffer
// 
// @param e - EBPF event to convert
func newBindEventDataFromEbpf(e bindEventData) *BindEventData {
	evt := &BindEventData{
		Args: [3]uint64{
			e.Args[0],
			e.Args[1],
			e.Args[2],
		},
	}
	return evt
}

type NetworkBindDetector struct {
	ebpfLink   link.Link
	perfReader *perf.Reader
}

// NewNetworkBindDetector creates a new instance of NetworkBindDetector.
func NewNetworkBindDetector() *NetworkBindDetector {
	return &NetworkBindDetector{}
}

// Start the NetworkBindDetector. If Start returns an error the NetworkBindDetector will not be started and the error will be returned.
// 
// @param o - The object to start. Must not be nil.
// 
// @return Error from kprobes. Start or any error that occurs during initialization of the NetworkBindDetector.
func (o *NetworkBindDetector) Start() error {
	bpfObjs, err := getEbpfObject()
	// Returns the error if any.
	if err != nil {
		return err
	}

	l, err := link.Kprobe("__x64_sys_bind", bpfObjs.KprobeBind, nil)
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

// Close closes the EBPF link and perf reader. It is safe to call multiple times. If Close fails it will return the first error encountered.
// 
// @param o - The object to close. Must not be nil.
// 
// @return An error if any occurred during closing or nil otherwise. This may be non nil if the error was encountered while closing
func (o *NetworkBindDetector) Close() error {
	err := o.ebpfLink.Close()
	// Returns the error if any.
	if err != nil {
		return err
	}

	return o.perfReader.Close()
}

// Read reads and returns the next EBPF event from the perf reader. It is expected that Read will be called before any other methods of NetworkBindDetector have been called.
// 
// @param o - the instance of NetworkBindDetector to read from
func (o *NetworkBindDetector) Read() (*BindEventData, error) {
	var ebpfEvent bindEventData
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

	exportedEvent := newBindEventDataFromEbpf(ebpfEvent)
	return exportedEvent, nil
}

// ReadAsInterface implements the BindDetector interface. This is a no op for NetworkBindDetector since it does not return anything
// 
// @param o
func (o *NetworkBindDetector) ReadAsInterface() (any, error) {
	return o.Read()
}


func printToScreen(e bindEventData) {
	fmt.Println("-----------------------------------------")
	fmt.Printf("Bind_File_descriptor: %d\n", e.Args[0])
	fmt.Printf("Bind_address : %s\n", IPv6(e.Args[1]))

	fmt.Println("-----------------------------------------")
}


// IPv6 converts an uint64 to string. The string is in big endian format
// 
// @param in - the uint64 to convert to string
// 
// @return the string representation of the uint64 in big endian format or empty string if not valid or not a
func IPv6(in uint64) string {

	ip := make(net.IP, net.IPv6len)
	binary.BigEndian.PutUint64(ip, in)
	return ip.String()
}
