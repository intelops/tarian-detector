// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package tarian

import (
	"errors"
	"fmt"

	e "github.com/cilium/ebpf"
	ebpf "github.com/intelops/tarian-detector/pkg/eBPF"
	"github.com/intelops/tarian-detector/pkg/utils"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type tarian_meta_data_t -target $CURR_ARCH tarian c/tarian.bpf.c -- -I../headers -I./c

func GetModule() (*ebpf.Module, error) {

	bpfObjs, err := getBpfObject()
	if err != nil {
		var verr *e.VerifierError
		if errors.As(err, &verr) {
			fmt.Printf("HERE: %+v\n", verr)
		}
		return nil, err
	}

	tarianDetectorModule := ebpf.NewModule("tarian_detector")
	ckv, err := utils.CurrentKernelVersion()
	if err != nil {
		return nil, err
	}

	if ckv >= utils.KernelVersion(5, 8, 0) {
		tarianDetectorModule.Map(ebpf.NewArrayOfRingBuf(bpfObjs.Events))
	} else {
		tarianDetectorModule.Map(ebpf.NewPerfEventWithBuffer(bpfObjs.Events, bpfObjs.PeaPerCpuArray))
	}

	tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfExecveE, ebpf.NewHookInfo().Kprobe("__x64_sys_execve")))
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.ExecveR, ebpf.NewHookInfo().Kretprobe("__x64_sys_openat")))

	// // kprobe & kretprobe clone
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KprobeClone, ebpf.NewHookInfo().Kprobe("__x64_sys_clone")))
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeClone, ebpf.NewHookInfo().Kretprobe("__x64_sys_clone")))

	// // kprobe & kretprobe execve
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KprobeExecve, ebpf.NewHookInfo().Kprobe("__x64_sys_execve")))
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeExecve, ebpf.NewHookInfo().Kretprobe("__x64_sys_execve")))

	// // kprobe & kretprobe execveat
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeExecveat, ebpf.NewHookInfo().Kprobe("__x64_sys_execveat")))
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeExecveat, ebpf.NewHookInfo().Kretprobe("__x64_sys_execveat")))

	// // kprobe & kretprobe close
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KprobeClose, ebpf.NewHookInfo().Kprobe("__x64_sys_close")))
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeClose, ebpf.NewHookInfo().Kretprobe("__x64_sys_close")))

	// // kprobe & kretprobe open
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KprobeOpen, ebpf.NewHookInfo().Kprobe("__x64_sys_open")))
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeOpen, ebpf.NewHookInfo().Kretprobe("__x64_sys_open")))

	// // kprobe & kretprobe openat
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KprobeOpenat, ebpf.NewHookInfo().Kprobe("__x64_sys_openat")))
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeOpenat, ebpf.NewHookInfo().Kretprobe("__x64_sys_openat")))

	// // kprobe & kretprobe openat2
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KprobeOpenat2, ebpf.NewHookInfo().Kprobe("__x64_sys_openat2")))
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeOpenat2, ebpf.NewHookInfo().Kretprobe("__x64_sys_openat2")))

	// // kprobe & kretprobe read
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KprobeRead, ebpf.NewHookInfo().Kprobe("__x64_sys_read")))
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeRead, ebpf.NewHookInfo().Kretprobe("__x64_sys_read")))

	// // kprobe & kretprobe readv
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KprobeReadv, ebpf.NewHookInfo().Kprobe("__x64_sys_readv")))
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeReadv, ebpf.NewHookInfo().Kretprobe("__x64_sys_readv")))

	// // kprobe & kretprobe write
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KprobeWrite, ebpf.NewHookInfo().Kprobe("__x64_sys_write")))
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeWrite, ebpf.NewHookInfo().Kretprobe("__x64_sys_write")))

	// // kprobe & kretprobe writev
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KprobeWritev, ebpf.NewHookInfo().Kprobe("__x64_sys_writev")))
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeWritev, ebpf.NewHookInfo().Kretprobe("__x64_sys_writev")))

	// // kprobe & kretprobe listen
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KprobeListen, ebpf.NewHookInfo().Kprobe("__x64_sys_listen")))
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeListen, ebpf.NewHookInfo().Kretprobe("__x64_sys_listen")))

	// // kprobe & kretprobe socket
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KprobeSocket, ebpf.NewHookInfo().Kprobe("__x64_sys_socket")))
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeSocket, ebpf.NewHookInfo().Kretprobe("__x64_sys_socket")))

	// // kprobe & kretprobe accept
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KprobeAccept, ebpf.NewHookInfo().Kprobe("__x64_sys_accept")))
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeAccept, ebpf.NewHookInfo().Kretprobe("__x64_sys_accept")))

	// // kprobe & kretprobe bind
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KprobeBind, ebpf.NewHookInfo().Kprobe("__x64_sys_bind")))
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeBind, ebpf.NewHookInfo().Kretprobe("__x64_sys_bind")))

	// // kprobe & kretprobe connect
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KprobeConnect, ebpf.NewHookInfo().Kprobe("__x64_sys_connect")))
	// tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeConnect, ebpf.NewHookInfo().Kretprobe("__x64_sys_connect")))

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
