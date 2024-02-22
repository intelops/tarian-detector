// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package detector

import (
	"github.com/intelops/tarian-detector/pkg/err"
	"github.com/intelops/tarian-detector/pkg/eventparser"
)

var detectorErr = err.New("detector.detector")

type EventDetector interface {
	Count() int
	Close() error
	ReadAsInterface() ([]func() ([]byte, error), error)
}

type detectorReadReturn struct {
	eventData []byte
	err       error
}

type EventsDetector struct {
	detectors         []EventDetector
	eventQueue        chan detectorReadReturn
	started           bool
	closed            bool
	totalRecordsCount int
	totalDetectors    int
	probeRecordsCount map[string]int
}

func NewEventsDetector() *EventsDetector {
	return &EventsDetector{
		detectors:  make([]EventDetector, 0),
		eventQueue: make(chan detectorReadReturn, 8192*16),
		started:    false,
		closed:     false,

		probeRecordsCount: make(map[string]int),
		totalRecordsCount: 0,
		totalDetectors:    0,
	}
}

func (t *EventsDetector) Add(detector EventDetector) {
	t.detectors = append(t.detectors, detector)
	t.incrementDetectorCountBy(detector.Count())
}

func (t *EventsDetector) incrementDetectorCountBy(n int) {
	t.totalDetectors += n
}

func (t *EventsDetector) incrementTotalCount() {
	t.totalRecordsCount++
}

func (t *EventsDetector) GetTotalCount() int {
	return t.totalRecordsCount
}

func (t *EventsDetector) probeCount(probe string) {
	t.probeRecordsCount[probe]++
}

func (t *EventsDetector) GetProbeCount() map[string]int {
	return t.probeRecordsCount
}

func (t *EventsDetector) Start() error {
	for _, detector := range t.detectors {
		d := detector
		mapReaders, err := d.ReadAsInterface()
		if err != nil {
			return detectorErr.Throwf("%v", err)
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
			return detectorErr.Throwf("%v", err)
		}
	}

	return nil
}

func (t *EventsDetector) ReadAsInterface() (map[string]any, error) {
	eventparser.LoadTarianEvents()
	r := <-t.eventQueue
	if r.err != nil {
		return map[string]any{}, detectorErr.Throwf("%v", r.err)
	}

	t.incrementTotalCount()
	data, err := eventparser.ParseByteArray(r.eventData)
	if err != nil {
		return data, detectorErr.Throwf("%v", err)
	}

	probe, ok := data["eventId"]
	if ok {
		t.probeCount(probe.(string))
	}

	return data, nil
}

func (t *EventsDetector) Count() int {
	return t.totalDetectors
}
