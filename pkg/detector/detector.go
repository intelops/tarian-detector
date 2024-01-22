// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package detector

import (
	"github.com/cilium/ebpf/ringbuf"
	"github.com/intelops/tarian-detector/pkg/eventparser"
)

type EventDetector interface {
	Close() error
	ReadAsInterface() ([]func() ([]byte, error), error)
}

type detectorReadReturn struct {
	eventData []byte
	err       error
}

type EventsDetector struct {
	detectors  []EventDetector
	eventQueue chan detectorReadReturn
	started    bool
	closed     bool

	/*TODO: UPDATE THIS as unexported fields and provide getters and setters for this*/
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
		mapReaders, err := d.ReadAsInterface()
		if err != nil {
			return err
		}

		for _, reader := range mapReaders {
			go func(r func() ([]byte, error)) {
				for {
					if t.closed {
						return
					}

					event, err := r()
					if err == nil {
						if len(event) != 0 {
							t.eventQueue <- detectorReadReturn{event, err}
						}
					} else {
						t.eventQueue <- detectorReadReturn{[]byte{}, err}
					}
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

func (t *EventsDetector) ReadAsInterface() (map[string]any, error) {
	r := <-t.eventQueue
	if r.err != nil {
		return map[string]any{}, r.err
	}

	eventparser.LoadTarianEvents()
	data, err := eventparser.ParseByteArray(r.eventData)
	return data, err
}

func (t *EventsDetector) Count() int {
	return len(t.detectors)
}

func mapReader(r *ringbuf.Reader) (ringbuf.Record, error) {
	return r.Read()
}
