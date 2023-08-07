// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian
package network_bind

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -target $CURR_ARCH  -type event_data bind bind.bpf.c -- -I../../../../headers

// getEbpfObject loads the eBPF objects and returns a pointer to the bindObjects structure.
func getEbpfObject() (*bindObjects, error) {
	var bpfObj bindObjects
	err := loadBindObjects(&bpfObj, nil)
	// Return any error that occurs during loading.
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}

// BindEventData represents the data received from the eBPF program.
// BindEventData is the exported data from the eBPF struct counterpart
// The intention is to use the proper Go string instead of byte arrays from C.
// It makes it simpler to use and can generate proper json.
type BindEventData struct {
	Args [3]uint64
}

// newBindEventDataFromEbpf creates a new BindEventData instance from the given eBPF data.
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

// NetworkBindDetector represents the detector for network bind events using eBPF.
type NetworkBindDetector struct {
	ebpfLink   link.Link
	ringbufReader *ringbuf.Reader
}

// NewNetworkBindDetector creates a new instance of NetworkBindDetector.
func NewNetworkBindDetector() *NetworkBindDetector {
	return &NetworkBindDetector{}
}

// Start initializes the NetworkBindDetector and starts monitoring network bind events.
func (o *NetworkBindDetector) Start() error {
	bpfObjs, err := getEbpfObject()
	// Return any error that occurs during loading.
	if err != nil {
		return err
	}

	l, err := link.Kprobe("__x64_sys_bind", bpfObjs.KprobeBind, nil)
	// Return any error that occurs during creating the Kprobe link.
	if err != nil {
		return err
	}

	o.ebpfLink = l
	rd, err := ringbuf.NewReader(bpfObjs.Event)

	// Return any error that occurs during creating the  event reader.
	if err != nil {
		return err
	}

	o.ringbufReader = rd
	return nil
}

// Close stops the NetworkBindDetector and closes associated resources.
func (o *NetworkBindDetector) Close() error {
	err := o.ebpfLink.Close()
	// Return any error that occurs during closing the link.
	if err != nil {
		return err
	}

	return o.ringbufReader.Close()
}

// Read retrieves the BindEventData from the eBPF program.
func (o *NetworkBindDetector) Read() (*BindEventData, error) {
	var ebpfEvent bindEventData
	record, err := o.ringbufReader.Read()
	// Return any error that occurs during reading from the  event reader.
	if err != nil {
		// If the  reader is closed, return the error as is.
		if errors.Is(err, ringbufReader.ErrClosed) {
			return nil, err
		}
		return nil, err
	}

	// Read the raw sample from the record using binary.Read.
	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &ebpfEvent); err != nil {
		return nil, err
	}
	exportedEvent := newBindEventDataFromEbpf(ebpfEvent)
	return exportedEvent, nil
}

// ReadAsInterface implements the ReadAsInterface method of the ebpf.Exporter interface.
// It calls the Read method internally.
func (o *NetworkBindDetector) ReadAsInterface() (any, error) {
	return o.Read()
}


