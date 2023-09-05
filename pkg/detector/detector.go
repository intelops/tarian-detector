// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package detector

type EventDetector interface {
	Read() (map[string]any, error)
	Close() error
}

type detectorReadReturn struct {
	eventData map[string]any
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
		eventQueue: make(chan detectorReadReturn, 1),
		started:    false,
		closed:     false,

		ProbeRecordsCount: make(map[string]int),
		TotalRecordsCount: 0,
	}
}

func (t *EventsDetector) Add(detectors []EventDetector) {
	t.detectors = append(t.detectors, detectors...)
}

func (t *EventsDetector) Start() error {
	for _, detector := range t.detectors {
		d := detector
		go func() {
			for {
				if t.closed {
					return
				}

				event, err := d.Read()
				t.eventQueue <- detectorReadReturn{event, err}
			}
		}()
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

	if len(r.eventData) != 0 {
		t.TotalRecordsCount++
		t.ProbeRecordsCount[r.eventData["tarian_detector"].(string)]++

	}
	return r.eventData, r.err
}

func (t *EventsDetector) Count() int {
	return len(t.detectors)
}
