// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package ebpf

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/intelops/tarian-detector/pkg/err"
)

var mapErr = err.New("ebpf.map")

// MapInfoType is an integer type used to represent different types of eBPF maps.
type MapInfoType int

// MapInfo holds information about an eBPF map.
type MapInfo struct {
	mapType      MapInfoType
	bpfMap       *ebpf.Map
	bufferSize   int
	innerMapType MapInfoType
}

// Supported eBPF map types.
const (
	RingBuffer     MapInfoType = iota // RingBuffer represents a ring buffer eBPF map.
	PerfEventArray                    // PerfEventArray represents a perf event array eBPF map.
	ArrayOfMaps                       // ArrayOfMaps represents an array of maps eBPF map.
)

const (
	// ErrNilMapPointer is the error message for a nil pointer received, expected cilium/ebpf.Map pointer.
	ErrNilMapPointer string = "nil pointer received, expected cilium/ebpf.Map pointer"

	// ErrNilMapReader is the error message for a nil pointer received, expected pointer to cilium/ebpf map reader.
	ErrNilMapReader string = "nil pointer received, expected pointer to cilium/ebpf map reader"

	// ErrUnsupportedBpfMapType is the error message for an unsupported BPF map type.
	ErrUnsupportedBpfMapType string = "unsupported BPF map type: %v"

	// ErrUnsupportedMapReader is the error message for an unsupported cilium/ebpf map reader.
	ErrUnsupportedMapReader string = "unsupported cilium/ebpf map reader: %T"

	// ErrUnsupportedInnerBpfMapType is the error message for an unsupported BPF map type found within the array of maps.
	ErrUnsupportedInnerBpfMapType string = "unsupported BPF map type found within the array of maps: %v"
)

// NewRingBuf creates a new MapInfo for a ring buffer eBPF map.
func NewRingBuf(m *ebpf.Map) *MapInfo {
	return &MapInfo{
		mapType:      RingBuffer,
		bpfMap:       m,
		innerMapType: -1,
	}
}

// NewPerfEvent creates a new MapInfo for a perf event array eBPF map.
func NewPerfEvent(m *ebpf.Map) *MapInfo {
	return &MapInfo{
		mapType:      PerfEventArray,
		bpfMap:       m,
		bufferSize:   os.Getpagesize(),
		innerMapType: -1,
	}
}

// NewPerfEventWithBuffer creates a new MapInfo for a perf event array eBPF map with a specified buffer.
func NewPerfEventWithBuffer(m *ebpf.Map, b *ebpf.Map) *MapInfo {
	return &MapInfo{
		mapType:      PerfEventArray,
		bpfMap:       m,
		bufferSize:   int(b.ValueSize()),
		innerMapType: -1,
	}
}

// NewArrayOfPerfEvent creates a new MapInfo for an array of perf event array eBPF maps.
func NewArrayOfPerfEvent(m *ebpf.Map) *MapInfo {
	return &MapInfo{
		mapType:      ArrayOfMaps,
		bpfMap:       m,
		innerMapType: PerfEventArray,
	}
}

// NewArrayOfRingBuf creates a new MapInfo for an array of ring buffer eBPF maps.
func NewArrayOfRingBuf(m *ebpf.Map) *MapInfo {
	return &MapInfo{
		mapType:      ArrayOfMaps,
		innerMapType: RingBuffer,
		bpfMap:       m,
	}
}

// String returns a string representation of the MapInfo.
func (mi *MapInfo) String() string {
	return fmt.Sprintf("%+v", *mi)
}

// CreateReaders creates readers for the eBPF map.
func (mi *MapInfo) CreateReaders() ([]any, error) {
	var mr []any

	switch mi.mapType {
	case RingBuffer:
		rb, err := mi.ringbufReader()
		if err == nil {
			mr = append(mr, rb)
		}

		return mr, err
	case PerfEventArray:
		pf, err := mi.perfReader()
		if err == nil {
			mr = append(mr, pf)
		}

		return mr, err
	case ArrayOfMaps:
		return mi.arrayOfMapsReader()
	default:
		return nil, mapErr.Throwf(ErrUnsupportedBpfMapType, mi.mapType)
	}
}

// arrayOfMapsReader creates readers for an array of eBPF maps.
func (mi *MapInfo) arrayOfMapsReader() ([]any, error) {
	if mi.bpfMap == nil {
		return nil, mapErr.Throw(ErrNilMapPointer)
	}

	var arrMR []any
	for i := uint32(0); i < mi.bpfMap.MaxEntries(); i++ {
		var innerMap *ebpf.Map
		var currMap MapInfo

		if err := mi.bpfMap.Lookup(&i, &innerMap); err != nil {
			return nil, mapErr.Throwf("%v", err)
		}

		currMap.bpfMap = innerMap
		currMap.mapType = mi.innerMapType

		switch mi.innerMapType {
		case RingBuffer:
			rb, err := currMap.ringbufReader()
			if err != nil {
				return nil, mapErr.Throwf("%v", err)
			}

			arrMR = append(arrMR, rb)
		case PerfEventArray:
			pf, err := currMap.perfReader()
			if err != nil {
				return nil, mapErr.Throwf("%v", err)
			}

			arrMR = append(arrMR, pf)
		default:
			return nil, mapErr.Throwf(ErrUnsupportedInnerBpfMapType, mi.innerMapType)
		}
	}

	return arrMR, nil
}

// ringbufReader creates a reader for a ring buffer eBPF map.
func (mi *MapInfo) ringbufReader() (*ringbuf.Reader, error) {
	if mi.bpfMap == nil {
		return nil, mapErr.Throw(ErrNilMapReader)
	}

	r, err := ringbuf.NewReader(mi.bpfMap)
	if err != nil {
		return nil, mapErr.Throwf("%v", err)
	}

	return r, nil
}

// perfReader creates a reader for a perf event array eBPF map.
func (mi *MapInfo) perfReader() (*perf.Reader, error) {
	if mi.bpfMap == nil {
		return nil, mapErr.Throw(ErrNilMapReader)
	}

	p, err := perf.NewReader(mi.bpfMap, mi.bufferSize)
	if err != nil {
		return nil, mapErr.Throwf("%v", err)
	}

	return p, nil
}

// read creates functions to read from a list of readers.
func read(readers []any) ([]func() ([]byte, error), error) {
	var funcs []func() ([]byte, error)

	for _, reader := range readers {
		switch r := reader.(type) {
		case *ringbuf.Reader:
			f, err := readRingbuf(r)
			if err != nil {
				return nil, err
			}

			funcs = append(funcs, f)
		case *perf.Reader:
			f, err := readPerf(r)
			if err != nil {
				return nil, err
			}

			funcs = append(funcs, f)
		default:
			return nil, mapErr.Throwf(ErrUnsupportedMapReader, r)
		}
	}

	return funcs, nil
}

// readRingbuf creates a function to read from a ring buffer eBPF map.
func readRingbuf(r *ringbuf.Reader) (func() ([]byte, error), error) {
	if r == nil {
		return nil, mapErr.Throw(ErrNilMapReader)
	}

	return func() ([]byte, error) {
		record, err := r.Read()
		if err != nil {
			return nil, mapErr.Throwf("%v", err)
		}

		return record.RawSample, nil
	}, nil
}

// readPerf creates a function to read from a perf event array eBPF map.
func readPerf(pr *perf.Reader) (func() ([]byte, error), error) {
	if pr == nil {
		return nil, mapErr.Throw(ErrNilMapReader)
	}

	return func() ([]byte, error) {
		record, err := pr.Read()
		if err != nil {
			return nil, mapErr.Throwf("%v", err)
		}

		return record.RawSample, nil
	}, nil
}

// closeMapReaders closes all the readers in the provided slice.
func closeMapReaders(readers []any) error {
	for _, reader := range readers {
		switch mr := reader.(type) {
		case *perf.Reader:
			err := mr.Close()
			if err != nil {
				return mapErr.Throwf("%v", err)
			}
		case *ringbuf.Reader:
			err := mr.Close()
			if err != nil {
				return mapErr.Throwf("%v", err)
			}
		default:
			return mapErr.Throwf(ErrUnsupportedMapReader, mr)
		}
	}

	return nil
}

// GetMapType returns the type of the eBPF map.
func (mi *MapInfo) GetMapType() MapInfoType {
	return mi.mapType
}

// GetInnerMapType returns the type of the inner eBPF map.
func (mi *MapInfo) GetInnerMapType() MapInfoType {
	return mi.innerMapType
}

// GetBpfMap returns the actual eBPF map.
func (mi *MapInfo) GetBpfMap() *ebpf.Map {
	return mi.bpfMap
}

// GetBufferSize returns the size of the buffer for the eBPF map.
func (mi *MapInfo) GetBufferSize() int {
	return mi.bufferSize
}

// String returns a string representation of the MapInfoType.
func (mit MapInfoType) String() string {
	switch mit {
	case RingBuffer:
		return "RingBuffer"
	case PerfEventArray:
		return "PerfEventArray"
	case ArrayOfMaps:
		return "ArrayOfMaps"
	default:
		return fmt.Sprintf("unknown MapInfoType(%d)", int(mit))
	}
}
