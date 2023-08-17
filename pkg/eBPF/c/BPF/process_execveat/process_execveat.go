// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package process_execveat

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/intelops/tarian-detector/pkg/inspector/ebpf_manager"
	"github.com/intelops/tarian-detector/pkg/utils"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data -target $CURR_ARCH execveat execveat.bpf.c -- -I../../../../../headers -I../../

type ProcessExecveat struct{}

func NewExecveat() *ProcessExecveat {
	return &ProcessExecveat{}
}

// Tells how to create a ebpf program
func (pe *ProcessExecveat) NewEbpf() (ebpf_manager.EbpfModule, error) {
	var em ebpf_manager.EbpfModule

	bpfObjs, err := getEbpfObject()
	if err != nil {
		return em, err
	}

	em.Programs = []ebpf_manager.Program{
		{
			Id: "__x64_sys_execveat_entry",
			Hook: ebpf_manager.Hook{
				Type: ebpf_manager.Kprobe,
				Name: "__x64_sys_execveat",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Program:      bpfObjs.KprobeExecveatEntry,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_execveat_exit",
			Hook: ebpf_manager.Hook{
				Type: ebpf_manager.Kretprobe,
				Name: "__x64_sys_execveat",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Program:      bpfObjs.KretprobeExecveatExit,
			ShouldAttach: true,
		},
	}

	em.Data = &execveatEventData{}
	em.Map = bpfObjs.Event

	return em, nil
}

// Tells how to parse the information received from the ebpf program
func (pe *ProcessExecveat) DataParser(data any) (map[string]any, error) {
	event_data, ok := data.(*execveatEventData)
	if !ok {
		return nil, fmt.Errorf("type mismatch: expected %T received %T", event_data, data)
	}

	res_data := utils.SetContext(event_data.EventContext)

	// event specific information
	switch event_data.Id {
	case 0:
		res_data["id"] = "sys_execveat_entry"

		res_data["file_descriptor"] = event_data.Fd
		res_data["binary_file_path"] = utils.Uint8toString(event_data.BinaryFilepath[:])
		res_data["user_command"] = utils.Uint8ArrtoString(event_data.UserComm[:])
		res_data["environment_variables"] = utils.Uint8ArrtoStringArr(event_data.EnvVars[:])
		res_data["flags"] = event_data.Flags

	case 1:
		res_data["id"] = "sys_execveat_exit"

		res_data["return_value"] = event_data.Ret

	}

	return res_data, nil
}

// loads the ebpf specs like maps, programs
func getEbpfObject() (*execveatObjects, error) {
	var bpfObj execveatObjects
	err := loadExecveatObjects(&bpfObj, nil)
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}