// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian
package network_connect

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -target $CURR_ARCH  -type event_data connect connect.bpf.c -- -I../../../../headers

// getEbpfObject loads the eBPF objects and returns a pointer to the connectObjects structure.
func getEbpfObject() (*connectObjects, error) {
	var bpfObj connectObjects
	err := loadConnectObjects(&bpfObj, nil)
	// Return any error that occurs during loading.
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}

// ConnectEventData represents the data received from the eBPF program.
// ConnectEventData is the exported data from the eBPF struct counterpart
// The intention is to use the proper Go string instead of byte arrays from C.
// It makes it simpler to use and can generate proper json.
type ConnectEventData struct {
	Args [3]uint64
}

// newConnectEventDataFromEbpf creates a new ConnectEventData instance from the given eBPF data.
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

// NetworkConnectDetector represents the detector for network connect events using eBPF.
type NetworkConnectDetector struct {
	ebpfLink   link.Link
	perfReader *perf.Reader
}

// NewNetworkConnectDetector creates a new NetworkConnectDetector instance.
func NewNetworkConnectDetector() *NetworkConnectDetector {
	return &NetworkConnectDetector{}
}

// Start initializes the NetworkConnectDetector and starts monitoring network connect events.
func (o *NetworkConnectDetector) Start() error {
	// Load eBPF objects from the compiled C code.
	bpfObjs, err := getEbpfObject()
	// Return any error that occurs during loading.
	if err != nil {
		return err
	}

	l, err := link.Kprobe("__x64_sys_connect", bpfObjs.KprobeConnect, nil)
	// Return any error that occurs during creating the Kprobe link.
	if err != nil {
		return err
	}

	o.ebpfLink = l
	rd, err := perf.NewReader(bpfObjs.Event, os.Getpagesize())
	// Return any error that occurs during creating the perf event reader.
	if err != nil {
		return err
	}

	o.perfReader = rd
	return nil
}

// Close stops the NetworkConnectDetector and closes associated resources.
func (o *NetworkConnectDetector) Close() error {
	err := o.ebpfLink.Close()
	// Return any error that occurs during closing the link.
	if err != nil {
		return err
	}

	return o.perfReader.Close()
}

// Read retrieves the ConnectEventData from the eBPF program.
func (o *NetworkConnectDetector) Read() (*ConnectEventData, error) {
	var ebpfEvent connectEventData
	record, err := o.perfReader.Read()
	// Return any error that occurs during reading from the perf event reader.
	if err != nil {
		// If the perf reader is closed, return the error as is.
		if errors.Is(err, perf.ErrClosed) {
			return nil, err
		}
		return nil, err
	}

	// Read the raw sample from the record using binary.Read.
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

