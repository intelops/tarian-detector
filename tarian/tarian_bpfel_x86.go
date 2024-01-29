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
	tarianTarianEventsETDE_SYSCALL_EXECVE_E   tarianTarianEventsE = 2
	tarianTarianEventsETDE_SYSCALL_EXECVE_R   tarianTarianEventsE = 3
	tarianTarianEventsETDE_SYSCALL_EXECVEAT_E tarianTarianEventsE = 4
	tarianTarianEventsETDE_SYSCALL_EXECVEAT_R tarianTarianEventsE = 5
	tarianTarianEventsETDE_SYSCALL_CLONE_E    tarianTarianEventsE = 6
	tarianTarianEventsETDE_SYSCALL_CLONE_R    tarianTarianEventsE = 7
	tarianTarianEventsETDE_SYSCALL_CLOSE_E    tarianTarianEventsE = 8
	tarianTarianEventsETDE_SYSCALL_CLOSE_R    tarianTarianEventsE = 9
	tarianTarianEventsETDE_SYSCALL_READ_E     tarianTarianEventsE = 10
	tarianTarianEventsETDE_SYSCALL_READ_R     tarianTarianEventsE = 11
	tarianTarianEventsETDE_SYSCALL_WRITE_E    tarianTarianEventsE = 12
	tarianTarianEventsETDE_SYSCALL_WRITE_R    tarianTarianEventsE = 13
	tarianTarianEventsETDE_SYSCALL_OPEN_E     tarianTarianEventsE = 14
	tarianTarianEventsETDE_SYSCALL_OPEN_R     tarianTarianEventsE = 15
	tarianTarianEventsETDE_SYSCALL_READV_E    tarianTarianEventsE = 16
	tarianTarianEventsETDE_SYSCALL_READV_R    tarianTarianEventsE = 17
	tarianTarianEventsETDE_SYSCALL_WRITEV_E   tarianTarianEventsE = 18
	tarianTarianEventsETDE_SYSCALL_WRITEV_R   tarianTarianEventsE = 19
	tarianTarianEventsETDE_SYSCALL_OPENAT_E   tarianTarianEventsE = 20
	tarianTarianEventsETDE_SYSCALL_OPENAT_R   tarianTarianEventsE = 21
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
	TdfCloneE    *ebpf.ProgramSpec `ebpf:"tdf_clone_e"`
	TdfCloneR    *ebpf.ProgramSpec `ebpf:"tdf_clone_r"`
	TdfCloseE    *ebpf.ProgramSpec `ebpf:"tdf_close_e"`
	TdfCloseR    *ebpf.ProgramSpec `ebpf:"tdf_close_r"`
	TdfExecveE   *ebpf.ProgramSpec `ebpf:"tdf_execve_e"`
	TdfExecveR   *ebpf.ProgramSpec `ebpf:"tdf_execve_r"`
	TdfExecveatE *ebpf.ProgramSpec `ebpf:"tdf_execveat_e"`
	TdfExecveatR *ebpf.ProgramSpec `ebpf:"tdf_execveat_r"`
	TdfOpenE     *ebpf.ProgramSpec `ebpf:"tdf_open_e"`
	TdfOpenR     *ebpf.ProgramSpec `ebpf:"tdf_open_r"`
	TdfOpenatE   *ebpf.ProgramSpec `ebpf:"tdf_openat_e"`
	TdfOpenatR   *ebpf.ProgramSpec `ebpf:"tdf_openat_r"`
	TdfReadE     *ebpf.ProgramSpec `ebpf:"tdf_read_e"`
	TdfReadR     *ebpf.ProgramSpec `ebpf:"tdf_read_r"`
	TdfReadvE    *ebpf.ProgramSpec `ebpf:"tdf_readv_e"`
	TdfReadvR    *ebpf.ProgramSpec `ebpf:"tdf_readv_r"`
	TdfWriteE    *ebpf.ProgramSpec `ebpf:"tdf_write_e"`
	TdfWriteR    *ebpf.ProgramSpec `ebpf:"tdf_write_r"`
	TdfWritevE   *ebpf.ProgramSpec `ebpf:"tdf_writev_e"`
	TdfWritevR   *ebpf.ProgramSpec `ebpf:"tdf_writev_r"`
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
	TdfCloneE    *ebpf.Program `ebpf:"tdf_clone_e"`
	TdfCloneR    *ebpf.Program `ebpf:"tdf_clone_r"`
	TdfCloseE    *ebpf.Program `ebpf:"tdf_close_e"`
	TdfCloseR    *ebpf.Program `ebpf:"tdf_close_r"`
	TdfExecveE   *ebpf.Program `ebpf:"tdf_execve_e"`
	TdfExecveR   *ebpf.Program `ebpf:"tdf_execve_r"`
	TdfExecveatE *ebpf.Program `ebpf:"tdf_execveat_e"`
	TdfExecveatR *ebpf.Program `ebpf:"tdf_execveat_r"`
	TdfOpenE     *ebpf.Program `ebpf:"tdf_open_e"`
	TdfOpenR     *ebpf.Program `ebpf:"tdf_open_r"`
	TdfOpenatE   *ebpf.Program `ebpf:"tdf_openat_e"`
	TdfOpenatR   *ebpf.Program `ebpf:"tdf_openat_r"`
	TdfReadE     *ebpf.Program `ebpf:"tdf_read_e"`
	TdfReadR     *ebpf.Program `ebpf:"tdf_read_r"`
	TdfReadvE    *ebpf.Program `ebpf:"tdf_readv_e"`
	TdfReadvR    *ebpf.Program `ebpf:"tdf_readv_r"`
	TdfWriteE    *ebpf.Program `ebpf:"tdf_write_e"`
	TdfWriteR    *ebpf.Program `ebpf:"tdf_write_r"`
	TdfWritevE   *ebpf.Program `ebpf:"tdf_writev_e"`
	TdfWritevR   *ebpf.Program `ebpf:"tdf_writev_r"`
}

func (p *tarianPrograms) Close() error {
	return _TarianClose(
		p.TdfCloneE,
		p.TdfCloneR,
		p.TdfCloseE,
		p.TdfCloseR,
		p.TdfExecveE,
		p.TdfExecveR,
		p.TdfExecveatE,
		p.TdfExecveatR,
		p.TdfOpenE,
		p.TdfOpenR,
		p.TdfOpenatE,
		p.TdfOpenatR,
		p.TdfReadE,
		p.TdfReadR,
		p.TdfReadvE,
		p.TdfReadvR,
		p.TdfWriteE,
		p.TdfWriteR,
		p.TdfWritevE,
		p.TdfWritevR,
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
