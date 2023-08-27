// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package linker

import (
	"bytes"
	"encoding/binary"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Handler struct {
	ProbeId   string
	MapReader *ringbuf.Reader
	ProbeLink link.Link
	Data      any
	ParseData func(any) (map[string]any, error)
}

// reads the information from maps.
func (h *Handler) Read() (map[string]any, error) {
	record, err := h.MapReader.Read()
	if err != nil {
		return nil, err
	}

	err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, h.Data)
	if err != nil {
		return nil, err
	}

	tm, err := h.ParseData(h.Data)
	if err != nil {
		return nil, err
	}
	return tm, nil
}

// closes the maps and hooks
func (h *Handler) Close() error {
	err := h.ProbeLink.Close()
	if err != nil {
		return err
	}

	return h.MapReader.Close()
}
