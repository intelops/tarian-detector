// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian
package network_listen

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -target $CURR_ARCH  -type event_data listen listen.bpf.c -- -I../../../../headers

// getEbpfObject loads the eBPF objects from the compiled code and returns a pointer to the listenObjects structure.
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

// ListenEventData represents the data received from the eBPF program.ListenEventData is the exported data from the eBPF struct counterpart.
// The structure holds captured arguments of the probed function
// The intention is to use the proper Go string instead of byte arrays from C.
// It makes it simpler to use and can generate proper json.
type ListenEventData struct {
	Pid     uint32
	Tgid    uint32
	Uid     uint32
	Gid     uint32
	Fd      int32
	Backlog int32
}

// newListenEventDataFromEbpf creates a new ListenEventData instance from the given eBPF data.
func newListenEventDataFromEbpf(e listenEventData) *ListenEventData {
	evt := &ListenEventData{
			Pid :    	e.Pid,
			Tgid:     	e.Tgid,
			Uid:      	e.Uid,
			Gid: 		e.Gid,
			Fd:  		e.Fd,
			Backlog:    e.Backlog,
	}
	return evt
}

// NetworkListenDetector represents the detector for network listen events using eBPF.
type NetworkListenDetector struct {
	ebpfLink   link.Link
	ringbufReader *ringbuf.Reader
}

// NewNetworkListenDetector creates a new instance of NetworkListenDetector. 
func NewNetworkListenDetector() *NetworkListenDetector {
	return &NetworkListenDetector{}
}

// Start starts the NetworkListenDetector and sets up the required eBPF hooks. 
// It returns an error if the start-up process encounters any issues.
func (o *NetworkListenDetector) Start() error {
	// Load eBPF objects from the compiled code.
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
	rd, err := ringbuf.NewReader(bpfObjs.Event)

	// Returns the error if any.
	if err != nil {
		return err
	}

	o.ringbufReader = rd
	return nil
}

// Close stops the NetworkListenDetector and closes associated resources.
func (o *NetworkListenDetector) Close() error {
	err := o.ebpfLink.Close()
	// Returns the error if any.
	if err != nil {
		return err
	}

	return o.ringbufReader.Close()
}

// Read retrieves the ListenEventData from the eBPF program.
func (o *NetworkListenDetector) Read() (*ListenEventData, error) {
	var ebpfEvent listenEventData
	record, err := o.ringbufReader.Read()
	// Returns the error if any.
	if err != nil {
		// If the  reader is closed, return the error as is.
		if errors.Is(err, ringbuf.ErrClosed) {
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

// ReadAsInterface implements Interface.
func (o *NetworkListenDetector) ReadAsInterface() (any, error) {
	return o.Read()
}


