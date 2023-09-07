// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package process_execveat

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/bpf"
	"github.com/intelops/tarian-detector/pkg/utils"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data -target $CURR_ARCH execveat execveat.bpf.c -- -I../../../../../headers -I../../

type ProcessExecveat struct{}

func NewProcessExecveat() *ProcessExecveat {
	return &ProcessExecveat{}
}

// Tells how to create a ebpf program
func (pe *ProcessExecveat) NewModule() (bpf.BpfModule, error) {
	bm := bpf.NewBpfModule()

	bpfObjs, err := getEbpfObject()
	if err != nil {
		return bm, err
	}

	bm.Programs = []bpf.BpfProgram{
		{
			Id: "__x64_sys_execveat_entry",
			Hook: bpf.Hook{
				Type: bpf.Kprobe,
				Name: "__x64_sys_execveat",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Name:         bpfObjs.KprobeExecveatEntry,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_execveat_exit",
			Hook: bpf.Hook{
				Type: bpf.Kretprobe,
				Name: "__x64_sys_execveat",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Name:         bpfObjs.KretprobeExecveatExit,
			ShouldAttach: true,
		},
	}

	bm.Data = &execveatEventData{}
	bm.Map = bpfObjs.ExecveatEventMap
	bm.ParseData = parseData

	return bm, nil
}

// Tells how to parse the information received from the ebpf program
func parseData(data any) (map[string]any, error) {
	event_data, ok := data.(*execveatEventData)
	if !ok {
		return nil, fmt.Errorf("type mismatch: expected %T received %T", event_data, data)
	}

	res_data := utils.SetContext(event_data.EventContext)
	res_data["tarian_detector"] = "process_execveat"

	// event specific information
	switch event_data.Id {
	case 0:
		res_data["tarian_detector_hook"] = "__x64_sys_execveat_entry"

		res_data["file_descriptor"] = event_data.Fd
		res_data["binary_file_path"] = utils.Uint8toString(event_data.BinaryFilepath[:])
		res_data["user_command"] = utils.Uint8ArrtoString(event_data.UserComm[:])
		res_data["environment_variables"] = utils.Uint8ArrtoStringArr(event_data.EnvVars[:])
		res_data["flags"] = event_data.Flags

	case 1:
		res_data["tarian_detector_hook"] = "__x64_sys_execveat_exit"

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
