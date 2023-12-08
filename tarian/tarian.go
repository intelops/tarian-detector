// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package tarian

import ebpf "github.com/intelops/tarian-detector/pkg/eBPF"

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data_t -target $CURR_ARCH tarian c/tarian.bpf.c -- -I../headers -I./c

func GetEBPFModule() (*ebpf.Module, error) {
	bpfObjs, err := getBpfObject()
	if err != nil {
		return nil, err
	}

	detectors := ebpf.NewModule("tarian_detector")
	detectors.Map = ebpf.NewArrayOfRingBuf(bpfObjs.PercpuRb)

	// kprobe & kretprobe clone
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KprobeClone, ebpf.NewHookInfo().Kprobe("__x64_sys_clone")))
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeClone, ebpf.NewHookInfo().Kretprobe("__x64_sys_clone")))

	// kprobe & kretprobe execve
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KprobeExecve, ebpf.NewHookInfo().Kprobe("__x64_sys_execve")))
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeExecve, ebpf.NewHookInfo().Kretprobe("__x64_sys_execve")))

	// kprobe & kretprobe execveat
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeExecveat, ebpf.NewHookInfo().Kprobe("__x64_sys_execveat")))
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeExecveat, ebpf.NewHookInfo().Kretprobe("__x64_sys_execveat")))

	// kprobe & kretprobe close
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KprobeClose, ebpf.NewHookInfo().Kprobe("__x64_sys_close")))
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeClose, ebpf.NewHookInfo().Kretprobe("__x64_sys_close")))

	// kprobe & kretprobe open
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KprobeOpen, ebpf.NewHookInfo().Kprobe("__x64_sys_open")))
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeOpen, ebpf.NewHookInfo().Kretprobe("__x64_sys_open")))

	// kprobe & kretprobe openat
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KprobeOpenat, ebpf.NewHookInfo().Kprobe("__x64_sys_openat")))
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeOpenat, ebpf.NewHookInfo().Kretprobe("__x64_sys_openat")))

	// kprobe & kretprobe openat2
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KprobeOpenat2, ebpf.NewHookInfo().Kprobe("__x64_sys_openat2")))
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeOpenat2, ebpf.NewHookInfo().Kretprobe("__x64_sys_openat2")))

	// kprobe & kretprobe read
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KprobeRead, ebpf.NewHookInfo().Kprobe("__x64_sys_read")))
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeRead, ebpf.NewHookInfo().Kretprobe("__x64_sys_read")))

	// kprobe & kretprobe readv
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KprobeReadv, ebpf.NewHookInfo().Kprobe("__x64_sys_readv")))
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeReadv, ebpf.NewHookInfo().Kretprobe("__x64_sys_readv")))

	// kprobe & kretprobe write
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KprobeWrite, ebpf.NewHookInfo().Kprobe("__x64_sys_write")))
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeWrite, ebpf.NewHookInfo().Kretprobe("__x64_sys_write")))

	// kprobe & kretprobe writev
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KprobeWritev, ebpf.NewHookInfo().Kprobe("__x64_sys_writev")))
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeWritev, ebpf.NewHookInfo().Kretprobe("__x64_sys_writev")))

	// kprobe & kretprobe listen
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KprobeListen, ebpf.NewHookInfo().Kprobe("__x64_sys_listen")))
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeListen, ebpf.NewHookInfo().Kretprobe("__x64_sys_listen")))

	// kprobe & kretprobe socket
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KprobeSocket, ebpf.NewHookInfo().Kprobe("__x64_sys_socket")))
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeSocket, ebpf.NewHookInfo().Kretprobe("__x64_sys_socket")))

	// kprobe & kretprobe accept
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KprobeAccept, ebpf.NewHookInfo().Kprobe("__x64_sys_accept")))
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeAccept, ebpf.NewHookInfo().Kretprobe("__x64_sys_accept")))

	// kprobe & kretprobe bind
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KprobeBind, ebpf.NewHookInfo().Kprobe("__x64_sys_bind")))
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeBind, ebpf.NewHookInfo().Kretprobe("__x64_sys_bind")))

	// kprobe & kretprobe connect
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KprobeConnect, ebpf.NewHookInfo().Kprobe("__x64_sys_connect")))
	detectors.AddProgram(ebpf.NewProgram(bpfObjs.KretprobeConnect, ebpf.NewHookInfo().Kretprobe("__x64_sys_connect")))

	return detectors, nil
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
