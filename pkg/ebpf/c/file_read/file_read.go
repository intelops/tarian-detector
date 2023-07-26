// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package file_read

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data -target $CURR_ARCH read read.bpf.c -- -I../../../../headers

// loads the ebpf specs like maps, programs
func getEbpfObject() (*readObjects, error) {
	var bpfObj readObjects
	err := loadReadObjects(&bpfObj, nil)
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}

type ReadEventData struct {
	readEventData
}

type ReadDetector struct {
	ebpfLink      link.Link
	ringbufReader *ringbuf.Reader
}

// NewReadDetector returns a new instance of ReadDetector
func NewReadDetector() *ReadDetector {
	return &ReadDetector{}
}

// Start the close detector by attaching ebpf program to
// hook in kernel and opens the map to read the data.
// If it cannot be started an error is returned.
func (p *ReadDetector) Start() error {
	bpfObjs, err := getEbpfObject()
	if err != nil {
		return err
	}

	l, err := link.Kprobe("__x64_sys_read", bpfObjs.KprobeRead, nil)
	if err != nil {
		return err
	}

	p.ebpfLink = l

	rd, err := ringbuf.NewReader(bpfObjs.Event)
	if err != nil {
		return err
	}

	p.ringbufReader = rd
	return nil
}

// closes the EBPF objects.
func (p *ReadDetector) Close() error {
	err := p.ebpfLink.Close()
	if err != nil {
		return err
	}

	return p.ringbufReader.Close()
}

// reads the next event from the ringbuffer.
func (p *ReadDetector) Read() (ReadEventData, error) {
	var event ReadEventData
	// reads the data from ringbuffer
	record, err := p.ringbufReader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return event, err
		}
		return event, err
	}

	// read the raw sample from the record.RawSample
	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
		return event, err
	}

	return event, nil
}

// reads data from a ring buffer and returns it as an interface.
func (p *ReadDetector) ReadAsInterface() (any, error) {
	return p.Read()
}
