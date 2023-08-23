// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package file_open

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/intelops/tarian-detector/pkg/inspector/ebpf_manager"
	"github.com/intelops/tarian-detector/pkg/utils"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data -target $CURR_ARCH open open.bpf.c -- -I../../../../../headers -I../../

type FileOpen struct{}

func NewFileOpen() *FileOpen {
	return &FileOpen{}
}

func (fo *FileOpen) NewEbpf() (ebpf_manager.EbpfModule, error) {
	var em ebpf_manager.EbpfModule

	bpfObjs, err := getEbpfObject()
	if err != nil {
		return em, err
	}

	em.Programs = []ebpf_manager.Program{
		{
			Id: "__x64_sys_open_entry",
			Hook: ebpf_manager.Hook{
				Type: ebpf_manager.Kprobe,
				Name: "__x64_sys_open",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Program:      bpfObjs.KprobeOpenEntry,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_open_exit",
			Hook: ebpf_manager.Hook{
				Type: ebpf_manager.Kretprobe,
				Name: "__x64_sys_open",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Program:      bpfObjs.KretprobeOpenExit,
			ShouldAttach: true,
		},
	}

	em.Data = &openEventData{}
	em.Map = bpfObjs.Event

	return em, nil
}

func (fo *FileOpen) DataParser(data any) (map[string]any, error) {
	event_data, ok := data.(*openEventData)
	if !ok {
		return nil, fmt.Errorf("type mismatch: expected %T received %T", event_data, data)
	}

	res_data := utils.SetContext(event_data.EventContext)

	// event specific information
	switch event_data.Id {
	case 0:
		res_data["id"] = "sys_open_entry"

		res_data["filename"] = utils.Uint8toString(event_data.Filename[:])
		res_data["flags"] = event_data.Flags
		res_data["mode"] = event_data.Mode

	case 1:
		res_data["id"] = "sys_open_exit"

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
