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

// getEbpfObject loads the eBPF objects from the compiled  code.
func getEbpfObject() (*listenObjects, error) {
	var bpfObj listenObjects
	
	// Load eBPF objects from the compiled  code into bpfObj.
	err := loadListenObjects(&bpfObj, nil)
	// Returns nil err if any error occurs.
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}

// ListenEventData is the exported data from the eBPF struct counterpart.
// The structure holds captured arguments of the probed function
// The intention is to use the proper Go string instead of byte arrays from C.
// It makes it simpler to use and can generate proper json.
type ListenEventData struct {
	Args [3]uint64
}

// newListenEventDataFromEbpf converts a listen event to a struct. 
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

// NewNetworkListenDetector creates a new instance of NetworkListenDetector. 
func NewNetworkListenDetector() *NetworkListenDetector {
	return &NetworkListenDetector{}
}

// Start starts the NetworkListenDetector and sets up the required eBPF hooks. 
// It returns an error if the start-up process encounters any issues.
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

// Closes the NetworkListenDetector by stopping the eBPF hooks and releasing resources.
// @return An error if any occurred during closing.
func (o *NetworkListenDetector) Close() error {
	err := o.ebpfLink.Close()
	// Returns the error if any.
	if err != nil {
		return err
	}

	return o.perfReader.Close()
}

// Read reads and returns the next eBPF event from the network.
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
	exportedEvent := newListenEventDataFromEbpf(ebpfEvent)
	return exportedEvent, nil
}

// ReadAsInterface implements Interface.Reads data from a ring buffer and returns it as an interface.
// @param o
func (o *NetworkListenDetector) ReadAsInterface() (any, error) {
	return o.Read()
}


