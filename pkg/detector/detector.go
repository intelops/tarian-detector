// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package detector

import (
	"github.com/intelops/tarian-detector/pkg/err"
	"github.com/intelops/tarian-detector/pkg/eventparser"
)

var detectorErr = err.New("detector.detector")

// EventDetector is an interface for event detection.
type EventDetector interface {
	Count() int                                         // Count returns the number of detectors active.
	Close() error                                       // Close closes the event detector and returns any error encountered.
	ReadAsInterface() ([]func() ([]byte, error), error) // ReadAsInterface returns a slice of functions that each return a byte slice and an error.
}

// detectorReadReturn is a struct that represents the return value of a detector read operation.
type detectorReadReturn struct {
	eventData []byte // eventData contains the event data.
	err       error  // err contains any error that occurred during the operation.
}

// EventsDetector represents a detector for monitoring events.
type EventsDetector struct {
	detectors         []EventDetector         // detectors is a slice of event detectors.
	eventQueue        chan detectorReadReturn // eventQueue is a channel that contains the return value of a detector read operation.
	started           bool                    // started is a flag indicating whether the event detector is started.
	closed            bool                    // closed is a flag indicating whether the event detector is closed.
	totalRecordsCount int                     // totalRecordsCount is the total count of records.
	totalDetectors    int                     // totalDetectors is the total number of detectors.
	probeRecordsCount map[string]int          // probeRecordsCount is a map of probe names to their respective counts
}

// NewEventsDetector creates a new EventsDetector instance
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

// Add adds an event detector to the detector.
func (t *EventsDetector) Add(detector EventDetector) {
	t.detectors = append(t.detectors, detector)
	t.incrementDetectorCountBy(detector.Count())
}

// incrementDetectorCountBy increments the total number of detectors by n.
func (t *EventsDetector) incrementDetectorCountBy(n int) {
	t.totalDetectors += n
}

// incrementTotalCount increments the total number of records.
func (t *EventsDetector) incrementTotalCount() {
	t.totalRecordsCount++
}

// GetTotalCount returns the total number of records.
func (t *EventsDetector) GetTotalCount() int {
	return t.totalRecordsCount
}

// probeCount increments the count of a probe.
func (t *EventsDetector) probeCount(probe string) {
	t.probeRecordsCount[probe]++
}

// GetProbeCount returns the count of probes.
func (t *EventsDetector) GetProbeCount() map[string]int {
	return t.probeRecordsCount
}

// Start initiates the event detection process. It iterates over the map of each detector,
// starts a goroutine for each map. These goroutines continuously read events from the maps
// and send them to the event queue. If the detector is closed, the goroutines stop reading events.
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

// Close closes the event detector.
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

// ReadAsInterface reads a byte array from the event queue, parses it, and increments the total count.
// It also checks for the presence of an event ID and increments the probe count if found.
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

// Count returns the number of detectors active.
func (t *EventsDetector) Count() int {
	return t.totalDetectors
}
