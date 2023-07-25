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

// newConnectEventDataFromEbpf converts a EBPF connect event to a Conn event. 
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

// NewNetworkConnectDetector creates a new instance of the network connect detector. 
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

// Close closes the EBPF link and perf reader. 
// @param o - NetworkConnectDetector to be closed. Must not be nil.
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
	exportedEvent := newConnectEventDataFromEbpf(ebpfEvent)
	return exportedEvent, nil
}

// ReadAsInterface implements Interface.
func (o *NetworkConnectDetector) ReadAsInterface() (any, error) {
	return o.Read()
}

