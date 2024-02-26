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

type MapInfoType int

type MapInfo struct {
	mapType      MapInfoType
	bpfMap       *ebpf.Map
	bufferSize   int
	innerMapType MapInfoType
}

// Supported ebpfmaps
const (
	RingBuffer MapInfoType = iota
	PerfEventArray
	ArrayOfMaps
)

const (
	ErrNilMapPointer              string = "nil pointer received, expected cilium/ebpf.Map pointer"
	ErrNilMapReader               string = "nil pointer received, expected pointer to cilium/ebpf map reader"
	ErrUnsupportedBpfMapType      string = "unsupported BPF map type: %v"
	ErrUnsupportedMapReader       string = "unsupported cilium/ebpf map reader: %T"
	ErrUnsupportedInnerBpfMapType string = "unsupported BPF map type found within the array of maps: %v"
)

var (
	mapErr = err.New("ebpf.map")
)

func NewRingBuf(m *ebpf.Map) *MapInfo {
	return &MapInfo{
		mapType:      RingBuffer,
		bpfMap:       m,
		innerMapType: -1,
	}
}

func NewPerfEvent(m *ebpf.Map) *MapInfo {
	return &MapInfo{
		mapType:      PerfEventArray,
		bpfMap:       m,
		bufferSize:   os.Getpagesize(),
		innerMapType: -1,
	}
}

func NewPerfEventWithBuffer(m *ebpf.Map, b *ebpf.Map) *MapInfo {
	return &MapInfo{
		mapType:      PerfEventArray,
		bpfMap:       m,
		bufferSize:   int(b.ValueSize()),
		innerMapType: -1,
	}
}

func NewArrayOfPerfEvent(m *ebpf.Map) *MapInfo {
	return &MapInfo{
		mapType:      ArrayOfMaps,
		bpfMap:       m,
		innerMapType: PerfEventArray,
	}
}

func NewArrayOfRingBuf(m *ebpf.Map) *MapInfo {
	return &MapInfo{
		mapType:      ArrayOfMaps,
		innerMapType: RingBuffer,
		bpfMap:       m,
	}
}

func (mi *MapInfo) String() string {
	return fmt.Sprintf("%+v", *mi)
}

func (mi *MapInfo) CreateReaders() ([]any, error) {
	var mr []any

	switch mi.mapType {
	case RingBuffer:
		rb, err := mi.ringbufReader()
		mr = append(mr, rb)

		return mr, err
	case PerfEventArray:
		pf, err := mi.perfReader()
		mr = append(mr, pf)

		return mr, err
	case ArrayOfMaps:
		return mi.arrayOfMapsReader()
	default:
		return nil, mapErr.Throwf(ErrUnsupportedBpfMapType, mi.mapType)
	}
}

func (mi *MapInfo) arrayOfMapsReader() ([]any, error) {
	if mi.bpfMap == nil {
		return nil, mapErr.Throw(ErrNilMapPointer)
	}

	var arrr []any
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

			arrr = append(arrr, rb)
		case PerfEventArray:
			pf, err := currMap.perfReader()
			if err != nil {
				return nil, mapErr.Throwf("%v", err)
			}

			arrr = append(arrr, pf)
		default:
			return nil, mapErr.Throwf(ErrUnsupportedInnerBpfMapType, mi.innerMapType)
		}
	}

	return arrr, nil
}

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

func (mi *MapInfo) GetMapType() MapInfoType {
	return mi.mapType
}

func (mi *MapInfo) GetInnerMapType() MapInfoType {
	return mi.innerMapType
}

func (mi *MapInfo) GetBpfMap() *ebpf.Map {
	return mi.bpfMap
}

func (mi *MapInfo) GetBufferSize() int {
	return mi.bufferSize
}

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
