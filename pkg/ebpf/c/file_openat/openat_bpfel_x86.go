// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64
// +build 386 amd64

package file_openat

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type openatEventData struct {
	Pid      uint32
	Tgid     uint32
	Uid      uint32
	Gid      uint32
	Filename [256]uint8
	Flags    int32
	Fd       int32
}

// loadOpenat returns the embedded CollectionSpec for openat.
func loadOpenat() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_OpenatBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load openat: %w", err)
	}

	return spec, err
}

// loadOpenatObjects loads openat and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*openatObjects
//	*openatPrograms
//	*openatMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadOpenatObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadOpenat()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// openatSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type openatSpecs struct {
	openatProgramSpecs
	openatMapSpecs
}

// openatSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type openatProgramSpecs struct {
	KprobeOpenat *ebpf.ProgramSpec `ebpf:"kprobe_openat"`
}

// openatMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type openatMapSpecs struct {
	Event *ebpf.MapSpec `ebpf:"event"`
}

// openatObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadOpenatObjects or ebpf.CollectionSpec.LoadAndAssign.
type openatObjects struct {
	openatPrograms
	openatMaps
}

func (o *openatObjects) Close() error {
	return _OpenatClose(
		&o.openatPrograms,
		&o.openatMaps,
	)
}

// openatMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadOpenatObjects or ebpf.CollectionSpec.LoadAndAssign.
type openatMaps struct {
	Event *ebpf.Map `ebpf:"event"`
}

func (m *openatMaps) Close() error {
	return _OpenatClose(
		m.Event,
	)
}

// openatPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadOpenatObjects or ebpf.CollectionSpec.LoadAndAssign.
type openatPrograms struct {
	KprobeOpenat *ebpf.Program `ebpf:"kprobe_openat"`
}

func (p *openatPrograms) Close() error {
	return _OpenatClose(
		p.KprobeOpenat,
	)
}

func _OpenatClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed openat_bpfel_x86.o
var _OpenatBytes []byte
