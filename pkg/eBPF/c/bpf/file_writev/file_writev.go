// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package file_writev

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/bpf"
	"github.com/intelops/tarian-detector/pkg/utils"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data -target $CURR_ARCH writev writev.bpf.c -- -I../../../../../headers -I../../

type FileWritev struct{}

func NewFileWritev() *FileWritev {
	return &FileWritev{}
}

func (fwv *FileWritev) NewModule() (bpf.BpfModule, error) {
	bm := bpf.NewBpfModule()

	bpfObjs, err := getEbpfObject()
	if err != nil {
		return bm, err
	}

	bm.Programs = []bpf.BpfProgram{
		{
			Id: "__x64_sys_writev_entry",
			Hook: bpf.Hook{
				Type: bpf.Kprobe,
				Name: "__x64_sys_writev",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Name:         bpfObjs.KprobeWritevEntry,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_writev_exit",
			Hook: bpf.Hook{
				Type: bpf.Kretprobe,
				Name: "__x64_sys_writev",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Name:         bpfObjs.KretprobeWritevExit,
			ShouldAttach: true,
		},
	}

	bm.Data = &writevEventData{}
	bm.Map = bpfObjs.WritevEventMap
	bm.ParseData = parseData

	return bm, nil
}

func parseData(data any) (map[string]any, error) {
	event_data, ok := data.(*writevEventData)
	if !ok {
		return nil, fmt.Errorf("type mismatch: expected %T received %T", event_data, data)
	}

	res_data := utils.SetContext(event_data.EventContext)

	// event specific information
	switch event_data.Id {
	case 0:
		res_data["tarian_detector"] = "__x64_sys_writev_entry"

		res_data["file_descriptor"] = event_data.Fd
		res_data["vlen"] = event_data.Vlen

	case 1:
		res_data["tarian_detector"] = "__x64_sys_writev_exit"

		res_data["return_value"] = event_data.Ret

	}

	return res_data, nil
}

// loads the ebpf specs like maps, programs
func getEbpfObject() (*writevObjects, error) {
	var bpfObj writevObjects
	err := loadWritevObjects(&bpfObj, nil)
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}
