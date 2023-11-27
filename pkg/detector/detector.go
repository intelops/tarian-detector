// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package detector

import (
	"fmt"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/intelops/tarian-detector/pkg/eventparser"
)

type EventDetector interface {
	Close() error
	ReadAsInterface() ([]*ringbuf.Reader, error)
}

type detectorReadReturn struct {
	eventData []byte
	restCount int
	err       error
}

type EventsDetector struct {
	detectors  []EventDetector
	eventQueue chan detectorReadReturn
	started    bool
	closed     bool

	ProbeRecordsCount map[string]int
	TotalRecordsCount int
}

func NewEventsDetector() *EventsDetector {
	return &EventsDetector{
		detectors:  make([]EventDetector, 0),
		eventQueue: make(chan detectorReadReturn, 8192*16),
		started:    false,
		closed:     false,

		ProbeRecordsCount: make(map[string]int),
		TotalRecordsCount: 0,
	}
}

func (t *EventsDetector) Add(detectors EventDetector) {
	t.detectors = append(t.detectors, detectors)
}

func (t *EventsDetector) Start() error {
	for _, detector := range t.detectors {
		d := detector
		mapReaders, _ := d.ReadAsInterface()
		fmt.Printf("Monitoring %d maps for data.\n", len(mapReaders))
		for _, reader := range mapReaders {
			go func(r *ringbuf.Reader) {
				for {
					if t.closed {
						return
					}

					event, err := mapReader(r)
					t.eventQueue <- detectorReadReturn{event.RawSample, event.Remaining, err}
				}
			}(reader)
		}
	}

	t.started = true

	return nil
}

func (t *EventsDetector) Close() error {
	t.closed = true

	for _, detector := range t.detectors {
		err := detector.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

func (t *EventsDetector) ReadAsInterface() (int, map[string]any, error) {
	r := <-t.eventQueue
	if r.err != nil {
		return r.restCount, map[string]any{}, r.err
	}

	data, err := eventparser.DecodeByte(r.eventData)
	return r.restCount, data, err
}

func (t *EventsDetector) Count() int {
	return len(t.detectors)
}

func mapReader(r *ringbuf.Reader) (ringbuf.Record, error) {
	return r.Read()
}
