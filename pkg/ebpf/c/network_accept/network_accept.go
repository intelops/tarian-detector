// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian
package network_accept

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -target $CURR_ARCH  -type event_data accept accept.bpf.c -- -I../../../../headers

// getEbpfObject loads the eBPF objects from the compiled code and returns a pointer to the acceptObjects structure.
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
	Args [3]uint64
}

// newAcceptEventDataFromEbpf converts an EBPF accept event to an AcceptEventData. 
//This is used to avoid having to copy the event data to a new EventData struct and to ensure that it is safe to modify the fields of the EventData struct before passing it to the event handler.
// @param e - the EBPF accept event to convert to an Accept
func newAcceptEventDataFromEbpf(e acceptEventData) *AcceptEventData {
	evt := &AcceptEventData{
		Args: [3]uint64{
			e.Args[0],
			e.Args[1],
			e.Args[2],
		},
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
		if errors.Is(err, ringbufReader.ErrClosed) {
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


