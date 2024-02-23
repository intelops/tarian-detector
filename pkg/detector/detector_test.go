// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package detector

import (
	"reflect"
	"testing"
)

// TestNewEventsDetector tests the NewEventsDetector function. It checks if the NewEventsDetector function returns an EventsDetector with the correct default values.
func TestNewEventsDetector(t *testing.T) {
	tests := []struct {
		name string
		want *EventsDetector
	}{
		{
			name: "default values",
			want: &EventsDetector{
				detectors:  make([]EventDetector, 0),
				eventQueue: make(chan detectorReadReturn, 8192*16),
				started:    false,
				closed:     false,

				probeRecordsCount: make(map[string]int),
				totalRecordsCount: 0,
				totalDetectors:    0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewEventsDetector()

			if reflect.TypeOf(got.detectors) != reflect.TypeOf(tt.want.detectors) {
				t.Errorf("NewEventsDetector().detectors has type %T, but expected type %T", got.detectors, tt.want.detectors)
			}

			if reflect.TypeOf(got.eventQueue) != reflect.TypeOf(tt.want.eventQueue) {
				t.Errorf("NewEventsDetector().eventQueue has type %T, but expected type %T", got.eventQueue, tt.want.eventQueue)
			}

			if cap(got.eventQueue) != cap(tt.want.eventQueue) {
				t.Errorf("NewEventsDetector().eventQueue has capacity %d, but expected capacity %d", cap(got.eventQueue), cap(tt.want.eventQueue))
			}

			if got.started != tt.want.started {
				t.Errorf("NewEventsDetector().started = %v, want %v", got.started, tt.want.started)
			}

			if got.closed != tt.want.closed {
				t.Errorf("NewEventsDetector().closed = %v, want %v", got.closed, tt.want.closed)
			}

			if reflect.TypeOf(got.probeRecordsCount) != reflect.TypeOf(tt.want.probeRecordsCount) {
				t.Errorf("NewEventsDetector().probeRecordsCount has type %T, but expected type %T", got.probeRecordsCount, tt.want.probeRecordsCount)
			}

			if got.totalRecordsCount != tt.want.totalRecordsCount {
				t.Errorf("NewEventsDetector().totalRecordsCount = %v, want %v", got.totalRecordsCount, tt.want.totalRecordsCount)
			}

			if got.totalDetectors != tt.want.totalDetectors {
				t.Errorf("NewEventsDetector().totalDetectors = %v, want %v", got.totalDetectors, tt.want.totalDetectors)
			}
		})
	}
}

// TestEventsDetector_Add tests the Add function.
func TestEventsDetector_Add(t *testing.T) {
	type fields struct {
		detectors         []EventDetector
		eventQueue        chan detectorReadReturn
		started           bool
		closed            bool
		totalRecordsCount int
		totalDetectors    int
		probeRecordsCount map[string]int
	}
	type args struct {
		detector EventDetector
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &EventsDetector{
				detectors:         tt.fields.detectors,
				eventQueue:        tt.fields.eventQueue,
				started:           tt.fields.started,
				closed:            tt.fields.closed,
				totalRecordsCount: tt.fields.totalRecordsCount,
				totalDetectors:    tt.fields.totalDetectors,
				probeRecordsCount: tt.fields.probeRecordsCount,
			}
			tr.Add(tt.args.detector)
		})
	}
}

// TestEventsDetector_incrementDetectorCountBy tests the incrementDetectorCountBy function.
func TestEventsDetector_incrementDetectorCountBy(t *testing.T) {
	type args struct {
		n int
	}
	tests := []struct {
		name   string
		fields EventsDetector
		args   args
		want   int
	}{
		{
			name:   "increment by 1",
			fields: *NewEventsDetector(),
			args: args{
				n: 1,
			},
			want: 1,
		}, {
			name:   "increment by 13",
			fields: *NewEventsDetector(),
			args: args{
				n: 13,
			},
			want: 13,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &EventsDetector{
				detectors:         tt.fields.detectors,
				eventQueue:        tt.fields.eventQueue,
				started:           tt.fields.started,
				closed:            tt.fields.closed,
				totalRecordsCount: tt.fields.totalRecordsCount,
				totalDetectors:    tt.fields.totalDetectors,
				probeRecordsCount: tt.fields.probeRecordsCount,
			}

			tr.incrementDetectorCountBy(tt.args.n)

			if tr.totalDetectors != tt.want {
				t.Errorf("EventsDetector.incrementDetectorCountBy() = %v, want %v", tr.totalDetectors, tt.want)
			}
		})
	}
}

// TestEventsDetector_incrementTotalCount tests the incrementTotalCount function.
func TestEventsDetector_incrementTotalCount(t *testing.T) {
	tests := []struct {
		name   string
		fields EventsDetector
		want   int
	}{
		{
			name:   "per call increment check",
			fields: *NewEventsDetector(),
			want:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &EventsDetector{
				detectors:         tt.fields.detectors,
				eventQueue:        tt.fields.eventQueue,
				started:           tt.fields.started,
				closed:            tt.fields.closed,
				totalRecordsCount: tt.fields.totalRecordsCount,
				totalDetectors:    tt.fields.totalDetectors,
				probeRecordsCount: tt.fields.probeRecordsCount,
			}
			tr.incrementTotalCount()

			if tr.totalRecordsCount != tt.want {
				t.Errorf("EventsDetector.incrementTotalCount() = %v, want %v", tr.totalRecordsCount, tt.want)
			}
		})
	}
}

// TestEventsDetector_GetTotalCount tests the GetTotalCount function.
func TestEventsDetector_GetTotalCount(t *testing.T) {
	tests := []struct {
		name            string
		fields          EventsDetector
		callIncrementBy int
		want            int
	}{
		{
			name:            "default",
			fields:          *NewEventsDetector(),
			callIncrementBy: 0,
			want:            0,
		},
		{
			name:            "per call increment check",
			fields:          *NewEventsDetector(),
			callIncrementBy: 1,
			want:            1,
		},
		{
			name:            "per call increment check",
			fields:          *NewEventsDetector(),
			callIncrementBy: 27,
			want:            27,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &EventsDetector{
				detectors:         tt.fields.detectors,
				eventQueue:        tt.fields.eventQueue,
				started:           tt.fields.started,
				closed:            tt.fields.closed,
				totalRecordsCount: tt.fields.totalRecordsCount,
				totalDetectors:    tt.fields.totalDetectors,
				probeRecordsCount: tt.fields.probeRecordsCount,
			}

			for i := 0; i < tt.callIncrementBy; i++ {
				tr.incrementTotalCount()

			}

			if got := tr.GetTotalCount(); got != tt.want {
				t.Errorf("EventsDetector.GetTotalCount() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestEventsDetector_probeCount tests the probeCount function.
func TestEventsDetector_probeCount(t *testing.T) {
	type args struct {
		probe string
	}

	type want struct {
		probe string
		count int
	}

	tests := []struct {
		name            string
		fields          EventsDetector
		args            args
		want            want
		callIncrementBy int
	}{
		{
			name:   "increment by 1",
			fields: *NewEventsDetector(),
			args: args{
				probe: "test",
			},
			callIncrementBy: 1,
			want: want{
				probe: "test",
				count: 1,
			},
		}, {
			name:   "increment by 38",
			fields: *NewEventsDetector(),
			args: args{
				probe: "test",
			},
			callIncrementBy: 38,
			want: want{
				probe: "test",
				count: 38,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &EventsDetector{
				detectors:         tt.fields.detectors,
				eventQueue:        tt.fields.eventQueue,
				started:           tt.fields.started,
				closed:            tt.fields.closed,
				totalRecordsCount: tt.fields.totalRecordsCount,
				totalDetectors:    tt.fields.totalDetectors,
				probeRecordsCount: tt.fields.probeRecordsCount,
			}

			for i := 0; i < tt.callIncrementBy; i++ {
				tr.probeCount(tt.args.probe)
			}

			if got := tr.probeRecordsCount[tt.want.probe]; got != tt.want.count {
				t.Errorf("EventsDetector.probeCount() = %v, want %v", got, tt.want.count)
			}
		})
	}
}

// TestEventsDetector_GetProbeCount tests the GetProbeCount function.
func TestEventsDetector_GetProbeCount(t *testing.T) {
	type args struct {
		probe string
	}

	tests := []struct {
		name            string
		fields          EventsDetector
		args            args
		callIncrementBy int
		want            map[string]int
	}{
		{
			name:   "default",
			fields: *NewEventsDetector(),
			args: args{
				probe: "test",
			},
			callIncrementBy: 0,
			want:            map[string]int{},
		},
		{
			name:   "per call increment check",
			fields: *NewEventsDetector(),
			args: args{
				probe: "test",
			},
			callIncrementBy: 1,
			want: map[string]int{
				"test": 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &EventsDetector{
				detectors:         tt.fields.detectors,
				eventQueue:        tt.fields.eventQueue,
				started:           tt.fields.started,
				closed:            tt.fields.closed,
				totalRecordsCount: tt.fields.totalRecordsCount,
				totalDetectors:    tt.fields.totalDetectors,
				probeRecordsCount: tt.fields.probeRecordsCount,
			}

			for i := 0; i < tt.callIncrementBy; i++ {
				tr.probeCount(tt.args.probe)
			}

			if got := tr.GetProbeCount(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("EventsDetector.GetProbeCount() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestEventsDetector_Count tests the Count function.
func TestEventsDetector_Count(t *testing.T) {
	tests := []struct {
		name            string
		fields          EventsDetector
		callIncrementBy int
		want            int
	}{
		{
			name:            "default",
			fields:          *NewEventsDetector(),
			callIncrementBy: 0,
			want:            0,
		}, {
			name:            "increment by 7",
			fields:          *NewEventsDetector(),
			callIncrementBy: 7,
			want:            7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &EventsDetector{
				detectors:         tt.fields.detectors,
				eventQueue:        tt.fields.eventQueue,
				started:           tt.fields.started,
				closed:            tt.fields.closed,
				totalRecordsCount: tt.fields.totalRecordsCount,
				totalDetectors:    tt.fields.totalDetectors,
				probeRecordsCount: tt.fields.probeRecordsCount,
			}

			tr.incrementDetectorCountBy(tt.callIncrementBy)

			if got := tr.Count(); got != tt.want {
				t.Errorf("EventsDetector.Count() = %v, want %v", got, tt.want)
			}
		})
	}
}
