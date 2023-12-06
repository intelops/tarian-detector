// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package file_read

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/bpf"
	"github.com/intelops/tarian-detector/pkg/utils"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data -target $CURR_ARCH read read.bpf.c -- -I../../../../../headers -I../../

type FileRead struct{}

func NewFileRead() *FileRead {
	return &FileRead{}
}

func (fr *FileRead) NewModule() (bpf.BpfModule, error) {
	bm := bpf.NewBpfModule()

	bpfObjs, err := getEbpfObject()
	if err != nil {
		return bm, err
	}

	bm.Programs = []bpf.BpfProgram{
		{
			Id: "__x64_sys_read_entry",
			Hook: bpf.Hook{
				Type: bpf.Kprobe,
				Name: "__x64_sys_read",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Name:         bpfObjs.KprobeReadEntry,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_read_exit",
			Hook: bpf.Hook{
				Type: bpf.Kretprobe,
				Name: "__x64_sys_read",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Name:         bpfObjs.KretprobeReadExit,
			ShouldAttach: true,
		},
	}

	bm.Data = &readEventData{}
	bm.Map = bpfObjs.ReadEventMap
	bm.ParseData = parseData

	return bm, nil
}

func parseData(data any) (map[string]any, error) {
	event_data, ok := data.(*readEventData)
	if !ok {
		return nil, fmt.Errorf("type mismatch: expected %T received %T", event_data, data)
	}

	res_data := utils.SetContext(event_data.EventContext)
	res_data["tarian_detector"] = "file_read"

	// event specific information
	switch event_data.Id {
	case 0:
		res_data["tarian_detector_hook"] = "__x64_sys_read_entry"

		res_data["file_descriptor"] = event_data.Fd
		res_data["count"] = event_data.Count

	case 1:
		res_data["tarian_detector_hook"] = "__x64_sys_read_exit"

		res_data["return_value"] = event_data.Ret
	}

	return res_data, nil
}

// loads the ebpf specs like maps, programs
func getEbpfObject() (*readObjects, error) {
	var bpfObj readObjects
	err := loadReadObjects(&bpfObj, nil)
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}
