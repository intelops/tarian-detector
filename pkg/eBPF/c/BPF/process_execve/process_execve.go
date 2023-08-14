// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package process_execve

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/intelops/tarian-detector/pkg/inspector/ebpf_manager"
	"github.com/intelops/tarian-detector/pkg/utils"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data -target $CURR_ARCH execve execve.bpf.c -- -I../../../../../headers -I../../

type ProcessExecve struct{}

func NewExecve() *ProcessExecve {
	return &ProcessExecve{}
}

// Tells how to create a ebpf program
func (pe *ProcessExecve) NewEbpf() (ebpf_manager.EbpfModule, error) {
	var em ebpf_manager.EbpfModule

	bpfObjs, err := getEbpfObject()
	if err != nil {
		return em, err
	}

	em.Programs = []ebpf_manager.Program{
		{
			Id: "__x64_sys_execve_entry",
			Hook: ebpf_manager.Hook{
				Type: ebpf_manager.Kprobe,
				Name: "__x64_sys_execve",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Program:      bpfObjs.KprobeExecveEntry,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_execve_exit",
			Hook: ebpf_manager.Hook{
				Type: ebpf_manager.Kretprobe,
				Name: "__x64_sys_execve",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Program:      bpfObjs.KretprobeExecveExit,
			ShouldAttach: true,
		},
	}

	em.Data = &execveEventData{}
	em.Map = bpfObjs.Event

	return em, nil
}

// Tells how to parse the information received from the ebpf program
func (pe *ProcessExecve) DataParser(data any) (map[string]any, error) {
	event_data, ok := data.(*execveEventData)
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
		res_data["id"] = "sys_execve_entry"

		res_data["binary_file_path"] = utils.Uint8toString(event_data.BinaryFilepath[:])
		res_data["full_command"] = utils.Uint8ArrtoString(event_data.UserComm[:])
		res_data["environment_variables"] = utils.Uint8ArrtoStringArr(event_data.EnvVars[:])

	case 1:
		res_data["id"] = "sys_execve_exit"

		res_data["return_value"] = event_data.Ret

	}

	return res_data, nil
}

// loads the ebpf specs like maps, programs
func getEbpfObject() (*execveObjects, error) {
	var bpfObj execveObjects
	err := loadExecveObjects(&bpfObj, nil)
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}
