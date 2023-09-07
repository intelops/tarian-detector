// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package file_openat2

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/bpf"
	"github.com/intelops/tarian-detector/pkg/utils"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data -target $CURR_ARCH openat2 openat2.bpf.c -- -I../../../../../headers -I../../

type FileOpenat2 struct{}

func NewFileOpenat2() *FileOpenat2 {
	return &FileOpenat2{}
}

func (fo2 *FileOpenat2) NewModule() (bpf.BpfModule, error) {
	bm := bpf.NewBpfModule()

	bpfObjs, err := getEbpfObject()
	if err != nil {
		return bm, err
	}

	bm.Programs = []bpf.BpfProgram{
		{
			Id: "__x64_sys_openat2_entry",
			Hook: bpf.Hook{
				Type: bpf.Kprobe,
				Name: "__x64_sys_openat2",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Name:         bpfObjs.KprobeOpenat2Entry,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_openat2_exit",
			Hook: bpf.Hook{
				Type: bpf.Kretprobe,
				Name: "__x64_sys_openat2",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Name:         bpfObjs.KretprobeOpenat2Exit,
			ShouldAttach: true,
		},
	}

	bm.Data = &openat2EventData{}
	bm.Map = bpfObjs.Openat2EventMap
	bm.ParseData = parseData

	return bm, nil
}

func parseData(data any) (map[string]any, error) {
	event_data, ok := data.(*openat2EventData)
	if !ok {
		return nil, fmt.Errorf("type mismatch: expected %T received %T", event_data, data)
	}

	res_data := utils.SetContext(event_data.EventContext)
	res_data["tarian_detector"] = "file_openat2"

	// event specific information
	switch event_data.Id {
	case 0:
		res_data["tarian_detector_hook"] = "__x64_sys_openat2_entry"

		res_data["file_descriptor"] = event_data.Fd
		res_data["filename"] = utils.Uint8toString(event_data.Filename[:])
		res_data["open_how"] = struct {
			Flags   uint64
			Mode    uint64
			Resolve uint64
		}{
			Flags:   event_data.How.Flags,
			Mode:    event_data.How.Mode,
			Resolve: event_data.How.Resolve,
		}

		res_data["usize"] = event_data.Usize

	case 1:
		res_data["tarian_detector_hook"] = "__x64_sys_openat2_exit"

		res_data["return_value"] = event_data.Ret
	}

	return res_data, nil
}

// loads the ebpf specs like maps, programs
func getEbpfObject() (*openat2Objects, error) {
	var bpfObj openat2Objects
	err := loadOpenat2Objects(&bpfObj, nil)
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}
