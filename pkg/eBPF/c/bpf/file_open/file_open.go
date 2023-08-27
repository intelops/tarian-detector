// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package file_open

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/bpf"
	"github.com/intelops/tarian-detector/pkg/utils"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data -target $CURR_ARCH open open.bpf.c -- -I../../../../../headers -I../../

type FileOpen struct{}

func NewFileOpen() *FileOpen {
	return &FileOpen{}
}

func (fo *FileOpen) NewModule() (bpf.BpfModule, error) {
	bm := bpf.NewBpfModule()

	bpfObjs, err := getEbpfObject()
	if err != nil {
		return bm, err
	}

	bm.Programs = []bpf.BpfProgram{
		{
			Id: "__x64_sys_open_entry",
			Hook: bpf.Hook{
				Type: bpf.Kprobe,
				Name: "__x64_sys_open",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Name:         bpfObjs.KprobeOpenEntry,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_open_exit",
			Hook: bpf.Hook{
				Type: bpf.Kretprobe,
				Name: "__x64_sys_open",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Name:         bpfObjs.KretprobeOpenExit,
			ShouldAttach: true,
		},
	}

	bm.Data = &openEventData{}
	bm.Map = bpfObjs.OpenEventMap
	bm.ParseData = parseData

	return bm, nil
}

func parseData(data any) (map[string]any, error) {
	event_data, ok := data.(*openEventData)
	if !ok {
		return nil, fmt.Errorf("type mismatch: expected %T received %T", event_data, data)
	}

	res_data := utils.SetContext(event_data.EventContext)

	// event specific information
	switch event_data.Id {
	case 0:
		res_data["id"] = "__x64_sys_open_entry"

		res_data["filename"] = utils.Uint8toString(event_data.Filename[:])
		res_data["flags"] = event_data.Flags
		res_data["mode"] = event_data.Mode

	case 1:
		res_data["id"] = "__x64_sys_open_exit"

		res_data["return_value"] = event_data.Ret

	}

	return res_data, nil
}

// loads the ebpf specs like maps, programs
func getEbpfObject() (*openObjects, error) {
	var bpfObj openObjects
	err := loadOpenObjects(&bpfObj, nil)
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}
