// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data_t -target $CURR_ARCH tarian c/tarian.bpf.c -- -I../../headers -I./c

func GetDetectors() (BpfModule, error) {
	var detectors BpfModule

	bpfObjs, err := getBpfObject()
	if err != nil {
		return detectors, err
	}

	detectors.Map = bpfObjs.PercpuRb
	detectors.Programs = []BpfProgram{
		{
			Id: "__x64_sys_execve_entry",
			Hook: Hook{
				Type: Kprobe,
				Name: "__x64_sys_execve",
				Opts: nil,
			},
			Name:         bpfObjs.KprobeExecve,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_execve_exit",
			Hook: Hook{
				Type: Kretprobe,
				Name: "__x64_sys_execve",
				Opts: nil,
			},
			Name:         bpfObjs.KretprobeExecve,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_execveat_entry",
			Hook: Hook{
				Type: Kprobe,
				Name: "__x64_sys_execveat",
				Opts: nil,
			},
			Name:         bpfObjs.KprobeExecveat,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_execveat_exit",
			Hook: Hook{
				Type: Kretprobe,
				Name: "__x64_sys_execveat",
				Opts: nil,
			},
			Name:         bpfObjs.KretprobeExecveat,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_close_entry",
			Hook: Hook{
				Type: Kprobe,
				Name: "__x64_sys_close",
				Opts: nil,
			},
			Name:         bpfObjs.KprobeClose,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_close_exit",
			Hook: Hook{
				Type: Kretprobe,
				Name: "__x64_sys_close",
				Opts: nil,
			},
			Name:         bpfObjs.KretprobeClose,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_open_entry",
			Hook: Hook{
				Type: Kprobe,
				Name: "__x64_sys_open",
				Opts: nil,
			},
			Name:         bpfObjs.KprobeOpen,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_open_exit",
			Hook: Hook{
				Type: Kretprobe,
				Name: "__x64_sys_open",
				Opts: nil,
			},
			Name:         bpfObjs.KretprobeOpen,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_openat_entry",
			Hook: Hook{
				Type: Kprobe,
				Name: "__x64_sys_openat",
				Opts: nil,
			},
			Name:         bpfObjs.KprobeOpenat,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_openat_exit",
			Hook: Hook{
				Type: Kretprobe,
				Name: "__x64_sys_openat",
				Opts: nil,
			},
			Name:         bpfObjs.KretprobeOpenat,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_openat2_entry",
			Hook: Hook{
				Type: Kprobe,
				Name: "__x64_sys_openat2",
				Opts: nil,
			},
			Name:         bpfObjs.KprobeOpenat2,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_openat2_exit",
			Hook: Hook{
				Type: Kretprobe,
				Name: "__x64_sys_openat2",
				Opts: nil,
			},
			Name:         bpfObjs.KretprobeOpenat2,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_read_entry",
			Hook: Hook{
				Type: Kprobe,
				Name: "__x64_sys_read",
				Opts: nil,
			},
			Name:         bpfObjs.KprobeRead,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_read_exit",
			Hook: Hook{
				Type: Kretprobe,
				Name: "__x64_sys_read",
				Opts: nil,
			},
			Name:         bpfObjs.KretprobeRead,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_readv_entry",
			Hook: Hook{
				Type: Kprobe,
				Name: "__x64_sys_readv",
				Opts: nil,
			},
			Name:         bpfObjs.KprobeReadv,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_readv_exit",
			Hook: Hook{
				Type: Kretprobe,
				Name: "__x64_sys_readv",
				Opts: nil,
			},
			Name:         bpfObjs.KretprobeReadv,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_write_entry",
			Hook: Hook{
				Type: Kprobe,
				Name: "__x64_sys_write",
				Opts: nil,
			},
			Name:         bpfObjs.KprobeWrite,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_write_exit",
			Hook: Hook{
				Type: Kretprobe,
				Name: "__x64_sys_write",
				Opts: nil,
			},
			Name:         bpfObjs.KretprobeWrite,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_writev_entry",
			Hook: Hook{
				Type: Kprobe,
				Name: "__x64_sys_writev",
				Opts: nil,
			},
			Name:         bpfObjs.KprobeWritev,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_writev_exit",
			Hook: Hook{
				Type: Kretprobe,
				Name: "__x64_sys_writev",
				Opts: nil,
			},
			Name:         bpfObjs.KretprobeWritev,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_listen_entry",
			Hook: Hook{
				Type: Kprobe,
				Name: "__x64_sys_listen",
				Opts: nil,
			},
			Name:         bpfObjs.KprobeListen,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_listen_exit",
			Hook: Hook{
				Type: Kretprobe,
				Name: "__x64_sys_listen",
				Opts: nil,
			},
			Name:         bpfObjs.KretprobeListen,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_socket_entry",
			Hook: Hook{
				Type: Kprobe,
				Name: "__x64_sys_socket",
				Opts: nil,
			},
			Name:         bpfObjs.KprobeSocket,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_socket_exit",
			Hook: Hook{
				Type: Kretprobe,
				Name: "__x64_sys_socket",
				Opts: nil,
			},
			Name:         bpfObjs.KretprobeSocket,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_accept_entry",
			Hook: Hook{
				Type: Kprobe,
				Name: "__x64_sys_accept",
				Opts: nil,
			},
			Name:         bpfObjs.KprobeAccept,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_accept_exit",
			Hook: Hook{
				Type: Kretprobe,
				Name: "__x64_sys_accept",
				Opts: nil,
			},
			Name:         bpfObjs.KretprobeAccept,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_bind_entry",
			Hook: Hook{
				Type: Kprobe,
				Name: "__x64_sys_bind",
				Opts: nil,
			},
			Name:         bpfObjs.KprobeBind,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_bind_exit",
			Hook: Hook{
				Type: Kretprobe,
				Name: "__x64_sys_bind",
				Opts: nil,
			},
			Name:         bpfObjs.KretprobeBind,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_connect_entry",
			Hook: Hook{
				Type: Kprobe,
				Name: "__x64_sys_connect",
				Opts: nil,
			},
			Name:         bpfObjs.KprobeConnect,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_connect_exit",
			Hook: Hook{
				Type: Kretprobe,
				Name: "__x64_sys_connect",
				Opts: nil,
			},
			Name:         bpfObjs.KretprobeConnect,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_clone_entry",
			Hook: Hook{
				Type: Kprobe,
				Name: "__x64_sys_clone",
				Opts: nil,
			},
			Name:         bpfObjs.KprobeClone,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_clone_exit",
			Hook: Hook{
				Type: Kretprobe,
				Name: "__x64_sys_clone",
				Opts: nil,
			},
			Name:         bpfObjs.KretprobeClone,
			ShouldAttach: true,
		},
	}

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
