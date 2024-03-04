// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package ebpf

import (
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
)

func dummy_ring_map(t *testing.T) *ebpf.Map {
	events, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.RingBuf,
		MaxEntries: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { events.Close() })
	return events
}

func dummy_percpuarray_map(t *testing.T) *ebpf.Map {
	events, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 4,
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { events.Close() })
	return events
}

func dummy_array_of_rb_map(t *testing.T) *ebpf.Map {
	inner := &ebpf.MapSpec{
		Name:       "inner_map",
		Type:       ebpf.RingBuf,
		MaxEntries: 4096,
	}
	im, err := ebpf.NewMap(inner)
	if err != nil {
		t.Fatal(err)
	}

	events, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.ArrayOfMaps,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 2,
		InnerMap:   inner,
		Contents: []ebpf.MapKV{
			{Key: uint32(0), Value: im},
			{Key: uint32(1), Value: im},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { events.Close() })
	return events
}

func dummy_array_of_rb_map_err(t *testing.T, size uint32) *ebpf.Map {
	inner := &ebpf.MapSpec{
		Name:       "inner_map",
		Type:       ebpf.RingBuf,
		MaxEntries: 4096,
	}
	im, err := ebpf.NewMap(inner)
	if err != nil {
		t.Fatal(err)
	}

	events, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.ArrayOfMaps,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: size,
		InnerMap:   inner,
		Contents: []ebpf.MapKV{
			{Key: uint32(0), Value: im},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { events.Close() })
	return events
}

func dummy_array_of_pea_map(t *testing.T) *ebpf.Map {
	inner := &ebpf.MapSpec{
		Type:       ebpf.PerfEventArray,
		MaxEntries: 4096,
	}
	im, err := ebpf.NewMap(inner)
	if err != nil {
		t.Fatal(err)
	}

	events, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.ArrayOfMaps,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 2,
		InnerMap:   inner,
		Contents: []ebpf.MapKV{
			{Key: uint32(0), Value: im},
			{Key: uint32(1), Value: im},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { events.Close() })
	return events
}

// TestNewRingBuf is function to test NewRingBuf
func TestNewRingBuf(t *testing.T) {
	ring := dummy_ring_map(t)

	type args struct {
		m *ebpf.Map
	}
	tests := []struct {
		name string
		args args
		want *MapInfo
	}{
		{
			name: "valid empty values",
			args: args{
				m: &ebpf.Map{},
			},
			want: &MapInfo{
				mapType:      RingBuffer,
				bpfMap:       &ebpf.Map{},
				innerMapType: -1,
			},
		},
		{
			name: "nil values",
			args: args{
				m: nil,
			},
			want: &MapInfo{
				mapType:      RingBuffer,
				bpfMap:       nil,
				innerMapType: -1,
			},
		},
		{
			name: "valid dummy map",
			args: args{
				m: ring,
			},
			want: &MapInfo{
				mapType:      RingBuffer,
				bpfMap:       ring,
				innerMapType: -1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewRingBuf(tt.args.m); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRingBuf() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNewPerfEvent is function to test NewPerfEvent
func TestNewPerfEvent(t *testing.T) {
	mapP := dummy_perf_map(t)

	type args struct {
		m *ebpf.Map
	}
	tests := []struct {
		name string
		args args
		want *MapInfo
	}{
		{
			name: "valid empty values",
			args: args{
				m: &ebpf.Map{},
			},
			want: &MapInfo{
				mapType:      PerfEventArray,
				bpfMap:       &ebpf.Map{},
				innerMapType: -1,
				bufferSize:   os.Getpagesize(),
			},
		},
		{
			name: "nil values",
			args: args{
				m: nil,
			},
			want: &MapInfo{
				mapType:      PerfEventArray,
				bpfMap:       nil,
				innerMapType: -1,
				bufferSize:   os.Getpagesize(),
			},
		},
		{
			name: "valid dummy map",
			args: args{
				m: mapP,
			},
			want: &MapInfo{
				mapType:      PerfEventArray,
				bpfMap:       mapP,
				innerMapType: -1,
				bufferSize:   os.Getpagesize(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewPerfEvent(tt.args.m); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewPerfEvent() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNewPerfEventWithBuffer is function to test NewPerfEventWithBuffer
func TestNewPerfEventWithBuffer(t *testing.T) {
	percpu := dummy_percpuarray_map(t)
	mapP := dummy_perf_map(t)

	type args struct {
		m *ebpf.Map
		b *ebpf.Map
	}
	tests := []struct {
		name string
		args args
		want *MapInfo
	}{
		{
			name: "valid empty values",
			args: args{
				m: &ebpf.Map{},
				b: percpu,
			},
			want: &MapInfo{
				mapType:      PerfEventArray,
				bpfMap:       &ebpf.Map{},
				innerMapType: -1,
				bufferSize:   4,
			},
		},
		{
			name: "nil values",
			args: args{
				m: nil,
				b: percpu,
			},
			want: &MapInfo{
				mapType:      PerfEventArray,
				bpfMap:       nil,
				innerMapType: -1,
				bufferSize:   4,
			},
		},
		{
			name: "valid dummy map",
			args: args{
				m: mapP,
				b: percpu,
			},
			want: &MapInfo{
				mapType:      PerfEventArray,
				bpfMap:       mapP,
				innerMapType: -1,
				bufferSize:   4,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewPerfEventWithBuffer(tt.args.m, tt.args.b); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewPerfEventWithBuffer() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNewArrayOfRingBuf is function to test NewArrayOfRingBuf
func TestNewArrayOfRingBuf(t *testing.T) {
	arrRb := dummy_array_of_rb_map(t)

	type args struct {
		m *ebpf.Map
	}
	tests := []struct {
		name string
		args args
		want *MapInfo
	}{
		{
			name: "valid empty values",
			args: args{
				m: &ebpf.Map{},
			},
			want: &MapInfo{
				mapType:      ArrayOfMaps,
				bpfMap:       &ebpf.Map{},
				innerMapType: RingBuffer,
				bufferSize:   0,
			},
		},
		{
			name: "nil values",
			args: args{
				m: nil,
			},
			want: &MapInfo{
				mapType:      ArrayOfMaps,
				bpfMap:       nil,
				innerMapType: RingBuffer,
			},
		},
		{
			name: "valid dummy map",
			args: args{
				m: arrRb,
			},
			want: &MapInfo{
				mapType:      ArrayOfMaps,
				bpfMap:       arrRb,
				innerMapType: RingBuffer,
				bufferSize:   0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewArrayOfRingBuf(tt.args.m); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewArrayOfRingBuf() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNewArrayOfPerfEvent is function to test NewArrayOfPerfEvent
func TestNewArrayOfPerfEvent(t *testing.T) {
	arrPf := dummy_array_of_pea_map(t)

	type args struct {
		m *ebpf.Map
	}
	tests := []struct {
		name string
		args args
		want *MapInfo
	}{
		{
			name: "valid empty values",
			args: args{
				m: &ebpf.Map{},
			},
			want: &MapInfo{
				mapType:      ArrayOfMaps,
				bpfMap:       &ebpf.Map{},
				innerMapType: PerfEventArray,
				bufferSize:   0,
			},
		},
		{
			name: "nil values",
			args: args{
				m: nil,
			},
			want: &MapInfo{
				mapType:      ArrayOfMaps,
				bpfMap:       nil,
				innerMapType: PerfEventArray,
			},
		},
		{
			name: "valid dummy map",
			args: args{
				m: arrPf,
			},
			want: &MapInfo{
				mapType:      ArrayOfMaps,
				bpfMap:       arrPf,
				innerMapType: PerfEventArray,
				bufferSize:   0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewArrayOfPerfEvent(tt.args.m); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewArrayOfPerfEvent() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestMapInfo_String is function to test MapInfo.String
func TestMapInfo_String(t *testing.T) {
	type fields struct {
		mapType      MapInfoType
		bpfMap       *ebpf.Map
		bufferSize   int
		innerMapType MapInfoType
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "valid values",
			fields: fields{
				mapType:      RingBuffer,
				bpfMap:       nil,
				bufferSize:   0,
				innerMapType: -1,
			},
			want: fmt.Sprintf("%+v", MapInfo{
				mapType:      RingBuffer,
				bpfMap:       nil,
				bufferSize:   0,
				innerMapType: -1,
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mi := &MapInfo{
				mapType:      tt.fields.mapType,
				bpfMap:       tt.fields.bpfMap,
				bufferSize:   tt.fields.bufferSize,
				innerMapType: tt.fields.innerMapType,
			}
			if got := mi.String(); got != tt.want {
				t.Errorf("MapInfo.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestMapInfo_CreateReaders is function to test MapInfo.CreateReaders
func TestMapInfo_CreateReaders(t *testing.T) {
	mapRb := dummy_ring_map(t)
	mapP := dummy_perf_map(t)
	arrRb := dummy_array_of_rb_map(t)

	type fields struct {
		mapType      MapInfoType
		bpfMap       *ebpf.Map
		bufferSize   int
		innerMapType MapInfoType
	}
	tests := []struct {
		name    string
		fields  fields
		want    int
		wantErr bool
	}{
		{
			name: "valid empty ringbuf values",
			fields: fields{
				mapType:      RingBuffer,
				bpfMap:       nil,
				bufferSize:   0,
				innerMapType: -1,
			},
			want:    0,
			wantErr: true,
		},
		{
			name: "valid dummy ringbuf",
			fields: fields{
				mapType:      RingBuffer,
				bpfMap:       mapRb,
				bufferSize:   8,
				innerMapType: -1,
			},
			want:    1,
			wantErr: false,
		},
		{
			name: "valid empty perf event values",
			fields: fields{
				mapType:      PerfEventArray,
				bpfMap:       nil,
				bufferSize:   0,
				innerMapType: -1,
			},
			want:    0,
			wantErr: true,
		},
		{
			name: "valid dummy ringbuf",
			fields: fields{
				mapType:      PerfEventArray,
				bpfMap:       mapP,
				bufferSize:   os.Getpagesize(),
				innerMapType: -1,
			},
			want:    1,
			wantErr: false,
		},
		{
			name: "nil map array of maps",
			fields: fields{
				mapType:      ArrayOfMaps,
				bpfMap:       nil,
				bufferSize:   0,
				innerMapType: RingBuffer,
			},
			want:    0,
			wantErr: true,
		},
		{
			name: "valid dummy array of ringbuf maps",
			fields: fields{
				mapType:      ArrayOfMaps,
				bpfMap:       arrRb,
				bufferSize:   0,
				innerMapType: RingBuffer,
			},
			want:    2,
			wantErr: false,
		},
		{
			name: "invalid dummy array of ringbuf maps",
			fields: fields{
				mapType:      ArrayOfMaps,
				bpfMap:       dummy_array_of_rb_map_err(t, 2),
				bufferSize:   0,
				innerMapType: RingBuffer,
			},
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mi := &MapInfo{
				mapType:      tt.fields.mapType,
				bpfMap:       tt.fields.bpfMap,
				bufferSize:   tt.fields.bufferSize,
				innerMapType: tt.fields.innerMapType,
			}
			got, err := mi.CreateReaders()
			if (err != nil) != tt.wantErr {
				t.Errorf("MapInfo.CreateReaders() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(got) != tt.want {
				t.Errorf("MapInfo.CreateReaders() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestMapInfo_GetMapType is function to test MapInfo.GetMapType
func TestMapInfo_GetMapType(t *testing.T) {
	type fields struct {
		mapType      MapInfoType
		bpfMap       *ebpf.Map
		bufferSize   int
		innerMapType MapInfoType
	}
	tests := []struct {
		name   string
		fields fields
		want   MapInfoType
	}{
		{
			name: "valid values",
			fields: fields{
				mapType:      RingBuffer,
				bpfMap:       nil,
				bufferSize:   0,
				innerMapType: -1,
			},
			want: RingBuffer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mi := &MapInfo{
				mapType:      tt.fields.mapType,
				bpfMap:       tt.fields.bpfMap,
				bufferSize:   tt.fields.bufferSize,
				innerMapType: tt.fields.innerMapType,
			}
			if got := mi.GetMapType(); got != tt.want {
				t.Errorf("MapInfo.GetMapType() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestMapInfo_GetInnerMapType is function to test MapInfo.GetInnerMapType
func TestMapInfo_GetInnerMapType(t *testing.T) {
	type fields struct {
		mapType      MapInfoType
		bpfMap       *ebpf.Map
		bufferSize   int
		innerMapType MapInfoType
	}
	tests := []struct {
		name   string
		fields fields
		want   MapInfoType
	}{
		{
			name: "valid values",
			fields: fields{
				mapType:      ArrayOfMaps,
				bpfMap:       nil,
				bufferSize:   0,
				innerMapType: RingBuffer,
			},
			want: RingBuffer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mi := &MapInfo{
				mapType:      tt.fields.mapType,
				bpfMap:       tt.fields.bpfMap,
				bufferSize:   tt.fields.bufferSize,
				innerMapType: tt.fields.innerMapType,
			}
			if got := mi.GetInnerMapType(); got != tt.want {
				t.Errorf("MapInfo.GetInnerMapType() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestMapInfo_GetBpfMap is function to test MapInfo.GetBpfMap
func TestMapInfo_GetBpfMap(t *testing.T) {
	type fields struct {
		mapType      MapInfoType
		bpfMap       *ebpf.Map
		bufferSize   int
		innerMapType MapInfoType
	}
	tests := []struct {
		name   string
		fields fields
		want   *ebpf.Map
	}{
		{
			name: "valid values",
			fields: fields{
				mapType:      RingBuffer,
				bpfMap:       nil,
				bufferSize:   0,
				innerMapType: -1,
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mi := &MapInfo{
				mapType:      tt.fields.mapType,
				bpfMap:       tt.fields.bpfMap,
				bufferSize:   tt.fields.bufferSize,
				innerMapType: tt.fields.innerMapType,
			}
			if got := mi.GetBpfMap(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MapInfo.GetBpfMap() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestMapInfo_GetBufferSize is function to test MapInfo.GetBufferSize
func TestMapInfo_GetBufferSize(t *testing.T) {
	type fields struct {
		mapType      MapInfoType
		bpfMap       *ebpf.Map
		bufferSize   int
		innerMapType MapInfoType
	}
	tests := []struct {
		name   string
		fields fields
		want   int
	}{
		{
			name: "valid values",
			fields: fields{
				mapType:      RingBuffer,
				bpfMap:       nil,
				bufferSize:   0,
				innerMapType: -1,
			},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mi := &MapInfo{
				mapType:      tt.fields.mapType,
				bpfMap:       tt.fields.bpfMap,
				bufferSize:   tt.fields.bufferSize,
				innerMapType: tt.fields.innerMapType,
			}
			if got := mi.GetBufferSize(); got != tt.want {
				t.Errorf("MapInfo.GetBufferSize() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestMapInfoType_String is function to test MapInfoType.String
func TestMapInfoType_String(t *testing.T) {
	tests := []struct {
		name string
		mit  MapInfoType
		want string
	}{
		{
			name: "valid ringbuf",
			mit:  RingBuffer,
			want: "RingBuffer",
		},
		{
			name: "valid perf",
			mit:  PerfEventArray,
			want: "PerfEventArray",
		},
		{
			name: "valid array of maps",
			mit:  ArrayOfMaps,
			want: "ArrayOfMaps",
		},
		{
			name: "invalid values",
			mit:  100,
			want: "unknown MapInfoType(100)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.mit.String(); got != tt.want {
				t.Errorf("MapInfoType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test_closeMapReaders is function to test closeMapReaders
func Test_closeMapReaders(t *testing.T) {
	mapP := dummy_perf_map(t)
	mapRb := dummy_ring_map(t)

	r, _ := ringbuf.NewReader(mapRb)
	p, _ := perf.NewReader(mapP, 4096)

	type args struct {
		readers []any
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid empty values",
			args: args{
				readers: []any{},
			},
			wantErr: false,
		},

		{
			name: "invalid values",
			args: args{
				readers: []any{mapP},
			},
			wantErr: true,
		},
		{
			name: "valid values",
			args: args{
				readers: []any{
					r, p,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := closeMapReaders(tt.args.readers); (err != nil) != tt.wantErr {
				t.Errorf("closeMapReaders() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
