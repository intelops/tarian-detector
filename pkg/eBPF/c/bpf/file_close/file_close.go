// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package file_close

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/bpf"
	"github.com/intelops/tarian-detector/pkg/utils"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data -target $CURR_ARCH close close.bpf.c -- -I../../../../../headers -I../../

type FileClose struct{}

func NewFileClose() *FileClose {
	return &FileClose{}
}

func (fc *FileClose) NewModule() (bpf.BpfModule, error) {
	bm := bpf.NewBpfModule()

	bpfObjs, err := getEbpfObject()
	if err != nil {
		return bm, err
	}

	bm.Programs = []bpf.BpfProgram{
		{
			Id: "__x64_sys_close_entry",
			Hook: bpf.Hook{
				Type: bpf.Kprobe,
				Name: "__x64_sys_close",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Name:         bpfObjs.KprobeCloseEntry,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_close_exit",
			Hook: bpf.Hook{
				Type: bpf.Kretprobe,
				Name: "__x64_sys_close",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Name:         bpfObjs.KretprobeCloseExit,
			ShouldAttach: true,
		},
	}

	bm.Data = &closeEventData{}
	bm.Map = bpfObjs.Event
	bm.ParseData = parseData

	return bm, nil
}

func parseData(data any) (map[string]any, error) {
	event_data, ok := data.(*closeEventData)
	if !ok {
		return nil, fmt.Errorf("type mismatch: expected %T received %T", event_data, data)
	}

	res_data := utils.SetContext(event_data.EventContext)

	// event specific information
	switch event_data.Id {
	case 0:
		res_data["id"] = "__x64_sys_close_entry"

		res_data["file_descriptor"] = event_data.Fd

	case 1:
		res_data["id"] = "__x64_sys_close_exit"

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
