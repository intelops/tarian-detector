// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package process_entry

import (
	"fmt"

	"github.com/intelops/tarian-detector/pkg/inspector/ebpf_manager"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data -target $CURR_ARCH entry entry.bpf.c -- -I../../../../../headers

type ProcessEntryEbpf struct{}

func NewProcessEntryEbpf() *ProcessEntryEbpf {
	return &ProcessEntryEbpf{}
}

func (pe *ProcessEntryEbpf) NewEbpf() (ebpf_manager.Program, error) {
	var ep ebpf_manager.Program
	ep.Name = "__x64_sys_execve"

	bpfObjs, err := getEbpfObject()
	if err != nil {
		return ep, err
	}

	ep.Program = bpfObjs.KprobeExecve
	ep.Map = bpfObjs.Event
	ep.Hook = ebpf_manager.Hook{
		Type: ebpf_manager.Kprobe,
		Name: "__x64_sys_execve",
		Opts: nil,
	}
	ep.Data = &entryEventData{}

	return ep, nil
}

func (pe *ProcessEntryEbpf) DataParser(data any) (map[string]any, error) {
	event_data, ok := data.(*entryEventData)
	if !ok {
		return nil, fmt.Errorf("type mismatch: expected %T received %T", event_data, data)
	}

	res_data := make(map[string]any)

	res_data["process_id"] = event_data.Pid
	res_data["thread_group_id"] = event_data.Tgid
	res_data["user_id"] = event_data.Uid
	res_data["group_id"] = event_data.Gid
	res_data["command"] = fmt.Sprintf("%s", event_data.Comm[:])
	res_data["current_working_directory"] = fmt.Sprintf("%s", event_data.Cwd[:])
	res_data["binary_file_path"] = fmt.Sprintf("%s", event_data.BinaryFilepath[:])

	return res_data, nil
}

// loads the ebpf specs like maps, programs
func getEbpfObject() (*entryObjects, error) {
	var bpfObj entryObjects
	err := loadEntryObjects(&bpfObj, nil)
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}
