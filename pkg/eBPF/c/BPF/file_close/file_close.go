// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package file_close

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/intelops/tarian-detector/pkg/inspector/ebpf_manager"
	"github.com/intelops/tarian-detector/pkg/utils"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data -target $CURR_ARCH close close.bpf.c -- -I../../../../../headers -I../../

type FileClose struct{}

func NewClose() *FileClose {
	return &FileClose{}
}

func (fc *FileClose) NewEbpf() (ebpf_manager.EbpfModule, error) {
	var em ebpf_manager.EbpfModule

	bpfObjs, err := getEbpfObject()
	if err != nil {
		return em, err
	}

	em.Programs = []ebpf_manager.Program{
		{
			Id: "__x64_sys_close_entry",
			Hook: ebpf_manager.Hook{
				Type: ebpf_manager.Kprobe,
				Name: "__x64_sys_close",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Program:      bpfObjs.KprobeCloseEntry,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_close_exit",
			Hook: ebpf_manager.Hook{
				Type: ebpf_manager.Kretprobe,
				Name: "__x64_sys_close",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Program:      bpfObjs.KretprobeCloseExit,
			ShouldAttach: true,
		},
	}

	em.Data = &closeEventData{}
	em.Map = bpfObjs.Event

	return em, nil
}

func (fc *FileClose) DataParser(data any) (map[string]any, error) {
	event_data, ok := data.(*closeEventData)
	if !ok {
		return nil, fmt.Errorf("type mismatch: expected %T received %T", event_data, data)
	}

	res_data := make(map[string]any)

	res_data["boot_time"] = utils.NanoSecToTimeFormat(event_data.E_ctx.Ts)
	res_data["start_time"] = utils.NanoSecToTimeFormat(event_data.E_ctx.StartTime)

	res_data["process_id"] = event_data.E_ctx.Pid
	res_data["thread_group_id"] = event_data.E_ctx.Tgid

	res_data["parent_process_id"] = event_data.E_ctx.Ppid
	res_data["group_leader_process_id"] = event_data.E_ctx.Glpid

	res_data["user_id"] = event_data.E_ctx.Uid
	res_data["group_id"] = event_data.E_ctx.Gid

	res_data["node_name"] = utils.Uint8toString(event_data.E_ctx.Nodename[:])

	res_data["command"] = utils.Uint8toString(event_data.E_ctx.Comm[:])

	res_data["current_working_directory"] = utils.Uint8toString(event_data.E_ctx.Cwd[:])

	// event specific information
	switch event_data.Id {
	case 0:
		res_data["id"] = "sys_close_entry"

		res_data["file_descriptor"] = event_data.Fd

	case 1:
		res_data["id"] = "sys_close_exit"

		res_data["return_value"] = event_data.Ret

	}

	return res_data, nil
}

// loads the ebpf specs like maps, programs
func getEbpfObject() (*closeObjects, error) {
	var bpfObj closeObjects
	err := loadCloseObjects(&bpfObj, nil)
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}
