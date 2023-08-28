// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package linker

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/bpf"
)

type Linker struct {
	ProbeIds           map[string]bool // Holds the Ids of attached bpf programs and attach status
	AttachCount        int             // Number of ebpf hooks attached
	AttachSkippedCount int             // Number of ebpf hooks skipped
	ProbeHandlers      []*Handler      // Bpf Programs Handler
}

// creates new instance of *Linker
func NewLinker() *Linker {
	return &Linker{
		ProbeIds:      make(map[string]bool),
		AttachCount:   0,
		ProbeHandlers: make([]*Handler, 0),
	}
}

func (l *Linker) Attach(bpfModule bpf.BpfModule) error {
	pMap, err := createMapReader(bpfModule.Map)
	if err != nil {
		return err
	}
	pParseData := bpfModule.ParseData
	pData := bpfModule.Data

	for _, prog := range bpfModule.Programs {
		l.ProbeIds[prog.Id] = prog.ShouldAttach

		if !prog.ShouldAttach {
			l.AttachSkippedCount++
			continue
		}

		var h Handler

		h.ProbeId = prog.Id
		h.MapReader = pMap
		h.Data = pData
		h.ParseData = pParseData

		pL, err := prog.AttachProbe()
		if err != nil {
			return err

		}

		h.ProbeLink = pL

		l.ProbeHandlers = append(l.ProbeHandlers, &h)
		l.AttachCount++
	}

	return nil
}

func createMapReader(name *ebpf.Map) (*ringbuf.Reader, error) {
	return ringbuf.NewReader(name)
}
