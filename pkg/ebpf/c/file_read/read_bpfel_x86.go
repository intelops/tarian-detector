// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64
// +build 386 amd64

package file_read

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type readEventData struct {
	Pid  uint32
	Tgid uint32
	Uid  uint32
	Gid  uint32
	Buf  [256]uint8
	Fd   uint32
}

// loadRead returns the embedded CollectionSpec for read.
func loadRead() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_ReadBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load read: %w", err)
	}

	return spec, err
}

// loadReadObjects loads read and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*readObjects
//	*readPrograms
//	*readMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadReadObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadRead()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// readSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type readSpecs struct {
	readProgramSpecs
	readMapSpecs
}

// readSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type readProgramSpecs struct {
	KprobeRead *ebpf.ProgramSpec `ebpf:"kprobe_read"`
}

// readMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type readMapSpecs struct {
	Event *ebpf.MapSpec `ebpf:"event"`
}

// readObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadReadObjects or ebpf.CollectionSpec.LoadAndAssign.
type readObjects struct {
	readPrograms
	readMaps
}

func (o *readObjects) Close() error {
	return _ReadClose(
		&o.readPrograms,
		&o.readMaps,
	)
}

// readMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadReadObjects or ebpf.CollectionSpec.LoadAndAssign.
type readMaps struct {
	Event *ebpf.Map `ebpf:"event"`
}

func (m *readMaps) Close() error {
	return _ReadClose(
		m.Event,
	)
}

// readPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadReadObjects or ebpf.CollectionSpec.LoadAndAssign.
type readPrograms struct {
	KprobeRead *ebpf.Program `ebpf:"kprobe_read"`
}

func (p *readPrograms) Close() error {
	return _ReadClose(
		p.KprobeRead,
	)
}

func _ReadClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed read_bpfel_x86.o
var _ReadBytes []byte