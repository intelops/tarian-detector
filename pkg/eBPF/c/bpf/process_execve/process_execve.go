// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package process_execve

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/bpf"
	"github.com/intelops/tarian-detector/pkg/utils"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data -target $CURR_ARCH execve execve.bpf.c -- -I../../../../../headers -I../../

type ProcessExecve struct{}

func NewProcessExecve() *ProcessExecve {
	return &ProcessExecve{}
}

// Tells how to create a ebpf program
func (pe *ProcessExecve) NewModule() (bpf.BpfModule, error) {
	bm := bpf.NewBpfModule()

	bpfObjs, err := getEbpfObject()
	if err != nil {
		return bm, err
	}

	bm.Programs = []bpf.BpfProgram{
		{
			Id: "__x64_sys_execve_entry",
			Hook: bpf.Hook{
				Type: bpf.Kprobe,
				Name: "__x64_sys_execve",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Name:         bpfObjs.KprobeExecveEntry,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_execve_exit",
			Hook: bpf.Hook{
				Type: bpf.Kretprobe,
				Name: "__x64_sys_execve",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Name:         bpfObjs.KretprobeExecveExit,
			ShouldAttach: true,
		},
	}

	bm.Data = &execveEventData{}
	bm.Map = bpfObjs.ExecveEventMap
	bm.ParseData = parseData

	return bm, nil
}

// Tells how to parse the information received from the ebpf program
func parseData(data any) (map[string]any, error) {
	event_data, ok := data.(*execveEventData)
	if !ok {
		return nil, fmt.Errorf("type mismatch: expected %T received %T", event_data, data)
	}

	res_data := utils.SetContext(event_data.EventContext)

	// event specific information
	switch event_data.Id {
	case 0:
		res_data["tarian_detector"] = "__x64_sys_execve_entry"

		res_data["binary_file_path"] = utils.Uint8toString(event_data.BinaryFilepath[:])
		res_data["full_command"] = utils.Uint8ArrtoString(event_data.UserComm[:])
		res_data["environment_variables"] = utils.Uint8ArrtoStringArr(event_data.EnvVars[:])

	case 1:
		res_data["tarian_detector"] = "__x64_sys_execve_exit"

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
