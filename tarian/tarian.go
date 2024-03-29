// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package tarian

import (
	"errors"

	cilium_ebpf "github.com/cilium/ebpf"
	ebpf "github.com/intelops/tarian-detector/pkg/eBPF"
	"github.com/intelops/tarian-detector/pkg/err"
	"github.com/intelops/tarian-detector/pkg/utils"
)

var tarianErr = err.New("tarian.tarian")

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -target $CURR_ARCH tarian c/tarian.bpf.c -- -I../headers -I./c

// GetModule loads the eBPF specifications, such as maps, programs, and structures, from a file.
// It returns a pointer to an ebpf.Module and an error, if any occurred during the loading process.
func GetModule() (*ebpf.Module, error) {
	bpfObjs, err := getBpfObject()
	if err != nil {
		var verr *cilium_ebpf.VerifierError
		if errors.As(err, &verr) {
			return nil, tarianErr.Throwf("%+v", verr)
		}

		return nil, tarianErr.Throwf("%v", err)
	}

	tarianDetectorModule := ebpf.NewModule("tarian_detector")
	ckv, err := utils.CurrentKernelVersion()
	if err != nil {
		return nil, tarianErr.Throwf("failed to get current kernel version: %v", err)
	}

	if ckv >= utils.KernelVersion(5, 8, 0) && false {
		tarianDetectorModule.Map(ebpf.NewArrayOfRingBuf(bpfObjs.Events))
	} else {
		tarianDetectorModule.Map(ebpf.NewPerfEventWithBuffer(bpfObjs.Events, bpfObjs.PeaPerCpuArray))
	}

	// kprobe & kretprobe execve
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfExecveE, ebpf.NewHookInfo().Kprobe("__x64_sys_execve")))
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfExecveR, ebpf.NewHookInfo().Kretprobe("__x64_sys_execve")))

	// kprobe & kretprobe execveat
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfExecveatE, ebpf.NewHookInfo().Kprobe("__x64_sys_execveat")))
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfExecveatR, ebpf.NewHookInfo().Kretprobe("__x64_sys_execveat")))

	// kprobe & kretprobe clone
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfCloneE, ebpf.NewHookInfo().Kprobe("__x64_sys_clone")))
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfCloneR, ebpf.NewHookInfo().Kretprobe("__x64_sys_clone")))

	// kprobe & kretprobe close
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfCloseE, ebpf.NewHookInfo().Kprobe("__x64_sys_close")))
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfCloseR, ebpf.NewHookInfo().Kretprobe("__x64_sys_close")))

	// kprobe & kretprobe read
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfReadE, ebpf.NewHookInfo().Kprobe("__x64_sys_read")))
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfReadR, ebpf.NewHookInfo().Kretprobe("__x64_sys_read")))

	// kprobe & kretprobe write
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfWriteE, ebpf.NewHookInfo().Kprobe("__x64_sys_write")))
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfWriteR, ebpf.NewHookInfo().Kretprobe("__x64_sys_write")))

	// kprobe & kretprobe open
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfOpenE, ebpf.NewHookInfo().Kprobe("__x64_sys_open")))
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfOpenR, ebpf.NewHookInfo().Kretprobe("__x64_sys_open")))

	// kprobe & kretprobe readv
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfReadvE, ebpf.NewHookInfo().Kprobe("__x64_sys_readv")))
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfReadvR, ebpf.NewHookInfo().Kretprobe("__x64_sys_readv")))

	// kprobe & kretprobe writev
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfWritevE, ebpf.NewHookInfo().Kprobe("__x64_sys_writev")))
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfWritevR, ebpf.NewHookInfo().Kretprobe("__x64_sys_writev")))

	// kprobe & kretprobe openat
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfOpenatE, ebpf.NewHookInfo().Kprobe("__x64_sys_openat")))
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfOpenatR, ebpf.NewHookInfo().Kretprobe("__x64_sys_openat")))

	// kprobe & kretprobe openat2
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfOpenat2E, ebpf.NewHookInfo().Kprobe("__x64_sys_openat2")))
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfOpenat2R, ebpf.NewHookInfo().Kretprobe("__x64_sys_openat2")))

	// kprobe & kretprobe listen
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfListenE, ebpf.NewHookInfo().Kprobe("__x64_sys_listen")))
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfListenR, ebpf.NewHookInfo().Kretprobe("__x64_sys_listen")))

	// kprobe & kretprobe socket
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfSocketE, ebpf.NewHookInfo().Kprobe("__x64_sys_socket")))
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfSocketR, ebpf.NewHookInfo().Kretprobe("__x64_sys_socket")))

	// kprobe & kretprobe accept
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfAcceptE, ebpf.NewHookInfo().Kprobe("__x64_sys_accept")))
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfAcceptR, ebpf.NewHookInfo().Kretprobe("__x64_sys_accept")))

	// kprobe & kretprobe bind
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfBindE, ebpf.NewHookInfo().Kprobe("__x64_sys_bind")))
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfBindR, ebpf.NewHookInfo().Kretprobe("__x64_sys_bind")))

	// kprobe & kretprobe connect
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfConnectE, ebpf.NewHookInfo().Kprobe("__x64_sys_connect")))
	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfConnectR, ebpf.NewHookInfo().Kretprobe("__x64_sys_connect")))

	return tarianDetectorModule, nil
}

// loads the ebpf specs like maps, programs
func getBpfObject() (*tarianObjects, error) {
	var bpfObj tarianObjects
	err := loadTarianObjects(&bpfObj, nil)
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}
