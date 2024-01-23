// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package tarian

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type tarianPerCpuBufferT struct{ Data [131072]uint8 }

type tarianScratchSpaceT struct {
	Data [8192]uint8
	Pos  uint64
}

type tarianTarianEventsE uint32

const (
	tarianTarianEventsETDE_SYSCALL_EXECVE_E tarianTarianEventsE = 2
	tarianTarianEventsETDE_SYSCALL_EXECVE_R tarianTarianEventsE = 3
	tarianTarianEventsETDE_SYSCALL_CLOSE_E  tarianTarianEventsE = 4
)

type tarianTarianMetaDataT struct {
	MetaData struct {
		Event     int32
		Nparams   uint8
		Syscall   int32
		Ts        uint64
		Processor uint16
		Task      struct {
			StartTime    uint64
			HostPid      uint32
			HostTgid     uint32
			HostPpid     uint32
			Pid          uint32
			Tgid         uint32
			Ppid         uint32
			Uid          uint32
			Gid          uint32
			CgroupId     uint64
			MountNsId    uint64
			PidNsId      uint64
			ExecId       uint64
			ParentExecId uint64
			Comm         [16]uint8
			Cwd          [256]uint8
		}
	}
	SystemInfo struct {
		Sysname    [65]uint8
		Nodename   [65]uint8
		Release    [65]uint8
		Version    [65]uint8
		Machine    [65]uint8
		Domainname [65]uint8
	}
}

// loadTarian returns the embedded CollectionSpec for tarian.
func loadTarian() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_TarianBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load tarian: %w", err)
	}

	return spec, err
}

// loadTarianObjects loads tarian and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*tarianObjects
//	*tarianPrograms
//	*tarianMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadTarianObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadTarian()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// tarianSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tarianSpecs struct {
	tarianProgramSpecs
	tarianMapSpecs
}

// tarianSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tarianProgramSpecs struct {
	TdfExecveE *ebpf.ProgramSpec `ebpf:"tdf_execve_e"`
	TdfExecveR *ebpf.ProgramSpec `ebpf:"tdf_execve_r"`
}

// tarianMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type tarianMapSpecs struct {
	ErbCpu0        *ebpf.MapSpec `ebpf:"erb_cpu0"`
	ErbCpu1        *ebpf.MapSpec `ebpf:"erb_cpu1"`
	ErbCpu10       *ebpf.MapSpec `ebpf:"erb_cpu10"`
	ErbCpu11       *ebpf.MapSpec `ebpf:"erb_cpu11"`
	ErbCpu12       *ebpf.MapSpec `ebpf:"erb_cpu12"`
	ErbCpu13       *ebpf.MapSpec `ebpf:"erb_cpu13"`
	ErbCpu14       *ebpf.MapSpec `ebpf:"erb_cpu14"`
	ErbCpu15       *ebpf.MapSpec `ebpf:"erb_cpu15"`
	ErbCpu2        *ebpf.MapSpec `ebpf:"erb_cpu2"`
	ErbCpu3        *ebpf.MapSpec `ebpf:"erb_cpu3"`
	ErbCpu4        *ebpf.MapSpec `ebpf:"erb_cpu4"`
	ErbCpu5        *ebpf.MapSpec `ebpf:"erb_cpu5"`
	ErbCpu6        *ebpf.MapSpec `ebpf:"erb_cpu6"`
	ErbCpu7        *ebpf.MapSpec `ebpf:"erb_cpu7"`
	ErbCpu8        *ebpf.MapSpec `ebpf:"erb_cpu8"`
	ErbCpu9        *ebpf.MapSpec `ebpf:"erb_cpu9"`
	Events         *ebpf.MapSpec `ebpf:"events"`
	PeaPerCpuArray *ebpf.MapSpec `ebpf:"pea_per_cpu_array"`
	ScratchSpace   *ebpf.MapSpec `ebpf:"scratch_space"`
}

// tarianObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadTarianObjects or ebpf.CollectionSpec.LoadAndAssign.
type tarianObjects struct {
	tarianPrograms
	tarianMaps
}

func (o *tarianObjects) Close() error {
	return _TarianClose(
		&o.tarianPrograms,
		&o.tarianMaps,
	)
}

// tarianMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadTarianObjects or ebpf.CollectionSpec.LoadAndAssign.
type tarianMaps struct {
	ErbCpu0        *ebpf.Map `ebpf:"erb_cpu0"`
	ErbCpu1        *ebpf.Map `ebpf:"erb_cpu1"`
	ErbCpu10       *ebpf.Map `ebpf:"erb_cpu10"`
	ErbCpu11       *ebpf.Map `ebpf:"erb_cpu11"`
	ErbCpu12       *ebpf.Map `ebpf:"erb_cpu12"`
	ErbCpu13       *ebpf.Map `ebpf:"erb_cpu13"`
	ErbCpu14       *ebpf.Map `ebpf:"erb_cpu14"`
	ErbCpu15       *ebpf.Map `ebpf:"erb_cpu15"`
	ErbCpu2        *ebpf.Map `ebpf:"erb_cpu2"`
	ErbCpu3        *ebpf.Map `ebpf:"erb_cpu3"`
	ErbCpu4        *ebpf.Map `ebpf:"erb_cpu4"`
	ErbCpu5        *ebpf.Map `ebpf:"erb_cpu5"`
	ErbCpu6        *ebpf.Map `ebpf:"erb_cpu6"`
	ErbCpu7        *ebpf.Map `ebpf:"erb_cpu7"`
	ErbCpu8        *ebpf.Map `ebpf:"erb_cpu8"`
	ErbCpu9        *ebpf.Map `ebpf:"erb_cpu9"`
	Events         *ebpf.Map `ebpf:"events"`
	PeaPerCpuArray *ebpf.Map `ebpf:"pea_per_cpu_array"`
	ScratchSpace   *ebpf.Map `ebpf:"scratch_space"`
}

func (m *tarianMaps) Close() error {
	return _TarianClose(
		m.ErbCpu0,
		m.ErbCpu1,
		m.ErbCpu10,
		m.ErbCpu11,
		m.ErbCpu12,
		m.ErbCpu13,
		m.ErbCpu14,
		m.ErbCpu15,
		m.ErbCpu2,
		m.ErbCpu3,
		m.ErbCpu4,
		m.ErbCpu5,
		m.ErbCpu6,
		m.ErbCpu7,
		m.ErbCpu8,
		m.ErbCpu9,
		m.Events,
		m.PeaPerCpuArray,
		m.ScratchSpace,
	)
}

// tarianPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadTarianObjects or ebpf.CollectionSpec.LoadAndAssign.
type tarianPrograms struct {
	TdfExecveE *ebpf.Program `ebpf:"tdf_execve_e"`
	TdfExecveR *ebpf.Program `ebpf:"tdf_execve_r"`
}

func (p *tarianPrograms) Close() error {
	return _TarianClose(
		p.TdfExecveE,
		p.TdfExecveR,
	)
}

func _TarianClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed tarian_bpfel_x86.o
var _TarianBytes []byte
