// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package ebpf

import (
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/intelops/tarian-detector/pkg/err"
)

type MapInfoType int

type MapInfo struct {
	Type         MapInfoType
	Map          *ebpf.Map
	InnerMapType MapInfoType
}

// Supported ebpfmaps
const (
	RingBuffer MapInfoType = iota
	PerfEventArray
	ArrayOfMaps
)

const (
	ErrNilMapPointer              string = "nil pointer received, expected cilium/ebpf.Map pointer"
	ErrNilMapReader                      = "nil pointer received, expected pointer to cilium/ebpf map reader"
	ErrUnsupportedBpfMapType             = "unsupported BPF map type: %v"
	ErrUnsupportedMapReader              = "unsupported cilium/ebpf map reader: %T"
	ErrUnsupportedInnerBpfMapType        = "unsupported BPF map type found within the array of maps: %v"
)

var (
	mapErr = err.New("ebpf.Map")
)

func NewRingBuf(m *ebpf.Map) *MapInfo {
	return &MapInfo{
		Type:         RingBuffer,
		Map:          m,
		InnerMapType: -1,
	}
}

func NewPerfEvent(m *ebpf.Map) *MapInfo {
	return &MapInfo{
		Type:         PerfEventArray,
		Map:          m,
		InnerMapType: -1,
	}
}

func NewArrayOfPerfEvent(m *ebpf.Map) *MapInfo {
	return &MapInfo{
		Type:         ArrayOfMaps,
		Map:          m,
		InnerMapType: PerfEventArray,
	}
}

func NewArrayOfRingBuf(m *ebpf.Map) *MapInfo {
	return &MapInfo{
		Type:         ArrayOfMaps,
		InnerMapType: RingBuffer,
		Map:          m,
	}
}

func (mi *MapInfo) CreateReaders() ([]any, error) {
	var mr []any

	switch mi.Type {
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
		return nil, mapErr.Throwf(ErrUnsupportedBpfMapType, mi.Type)
	}
}

func (mi *MapInfo) arrayOfMapsReader() ([]any, error) {
	if mi.Map == nil {
		return nil, mapErr.Throw(ErrNilMapPointer)
	}

	var arrr []any
	for i := uint32(0); i < mi.Map.MaxEntries(); i++ {
		var innerMap *ebpf.Map
		var currMap MapInfo

		if err := mi.Map.Lookup(&i, &innerMap); err != nil {
			return nil, mapErr.Throwf("%v", err)
		}

		currMap.Map = innerMap
		currMap.Type = mi.InnerMapType

		switch mi.InnerMapType {
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
			return nil, mapErr.Throwf(ErrUnsupportedInnerBpfMapType, mi.InnerMapType)
		}
	}

	return arrr, nil
}

func (mi *MapInfo) ringbufReader() (*ringbuf.Reader, error) {
	if mi.Map == nil {
		return nil, mapErr.Throw(ErrNilMapReader)
	}

	r, err := ringbuf.NewReader(mi.Map)
	if err != nil {
		return nil, mapErr.Throwf("%v", err)
	}

	return r, nil
}

func (mi *MapInfo) perfReader() (*perf.Reader, error) {
	if mi.Map == nil {
		return nil, mapErr.Throw(ErrNilMapReader)
	}

	p, err := perf.NewReader(mi.Map, os.Getpagesize())
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
			f, err := read_ringbuf(r)
			if err != nil {
				return nil, err
			}

			funcs = append(funcs, f)
		case *perf.Reader:
			var funcs []func() ([]byte, error)
			f, err := read_perf(r)
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

func read_ringbuf(r *ringbuf.Reader) (func() ([]byte, error), error) {
	if r == nil {
		return nil, mapErr.Throw(ErrNilMapReader)
	}

	return func() ([]byte, error) {
		record, err := r.Read()
		if err != nil {
			return nil, mapErr.Throwf("%vGo", err)
		}

		return record.RawSample, nil
	}, nil
}

func read_perf(pr *perf.Reader) (func() ([]byte, error), error) {
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
