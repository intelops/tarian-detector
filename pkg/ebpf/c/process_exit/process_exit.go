// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package process_exit

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -target $CURR_ARCH -type event_data exit exit.bpf.c -- -I../../../../headers

// loads the ebpf specs like maps, programs
func getEbpfObject() (*exitObjects, error) {
	var bpfObj exitObjects
	err := loadExitObjects(&bpfObj, nil)
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}

type ExitEventData struct {
	exitEventData
}

type ProcessExitDetector struct {
	ebpfLink      link.Link
	ringbufReader *ringbuf.Reader
}

// NewProcessExitDetector returns a new instance of ProcessExitDetector
func NewProcessExitDetector() *ProcessExitDetector {
	return &ProcessExitDetector{}
}

// Start the close detector by attaching ebpf program to
// hook in kernel and opens the map to read the data.
// If it cannot be started an error is returned.
func (p *ProcessExitDetector) Start() error {
	bpfObjs, err := getEbpfObject()
	if err != nil {
		return err
	}

	l, err := link.Tracepoint("syscalls", "sys_exit_execve", bpfObjs.ExecveExit, nil)
	if err != nil {
		return err
	}

	p.ebpfLink = l

	// Open a ringbuf reader from userspace RINGBUF map described in the
	// eBPF C program.
	rd, err := ringbuf.NewReader(bpfObjs.Event)
	if err != nil {
		return err
	}

	p.ringbufReader = rd
	return nil
}

// closes the EBPF objects
func (p *ProcessExitDetector) Close() error {
	err := p.ebpfLink.Close()
	if err != nil {
		return err
	}

	return p.ringbufReader.Close()
}

// reads the next event from the ringbuffer
func (p *ProcessExitDetector) Read() (ExitEventData, error) {
	var event ExitEventData
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

// reads data from a ring buffer and returns it as an interface
func (p *ProcessExitDetector) ReadAsInterface() (any, error) {
	return p.Read()
}
