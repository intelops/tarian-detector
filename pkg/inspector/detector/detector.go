// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package detector

type EventDetector struct {
	Close func() error
	Start func() (map[string]any, error)
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
}

func NewEventsDetector() *EventsDetector {
	return &EventsDetector{
		detectors:  make([]EventDetector, 0),
		eventQueue: make(chan detectorReadReturn, 1),
		started:    false,
		closed:     false,
	}
}

func (t *EventsDetector) Add(detector []EventDetector) {
	t.detectors = append(t.detectors, detector...)
}

func (t *EventsDetector) Start() error {
	for _, detector := range t.detectors {
		d := detector
		go func() {
			for {
				if t.closed {
					return
				}

				event, err := d.Start()
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

	return r.eventData, r.err
}

func (t *EventsDetector) Count() int {
	return len(t.detectors)
}
