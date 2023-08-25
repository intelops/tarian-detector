// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package network_listen

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/bpf"
	"github.com/intelops/tarian-detector/pkg/utils"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data -target $CURR_ARCH listen listen.bpf.c -- -I../../../../../headers -I../../

// NetworkListen is an empty struct that serves as a receiver for methods related to network listening.

type NetworkListen struct{}

// NewNetworkListen creates and returns a new instance of NetworkListen.
func NewNetworkListen() *NetworkListen {
	return &NetworkListen{}
}

// NewModule initializes a new BPF module for network binding and attaches necessary eBPF programs.
func (fo *NetworkListen) NewModule() (bpf.BpfModule, error) {
	bm := bpf.NewBpfModule()

	bpfObjs, err := getEbpfObject()
	if err != nil {
		return bm, err
	}

	bm.Programs = []bpf.BpfProgram{
		{
			Id: "__x64_sys_listen_entry",
			Hook: bpf.Hook{
				Type: bpf.Kprobe,
				Name: "__x64_sys_listen",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Name:         bpfObjs.KprobeListenEntry,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_listen_exit",
			Hook: bpf.Hook{
				Type: bpf.Kretprobe,
				Name: "__x64_sys_listen",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Name:         bpfObjs.KretprobeListenExit,
			ShouldAttach: true,
		},
	}

	bm.Data = &listenEventData{}
	bm.Map = bpfObjs.Event
	bm.ParseData = parseData

	return bm, nil
}

func parseData(data any) (map[string]any, error) {
	event_data, ok := data.(*listenEventData)
	if !ok {
		return nil, fmt.Errorf("type mismatch: expected %T received %T", event_data, data)
	}

	res_data := utils.SetContext(event_data.EventContext)

	// event specific information
	switch event_data.Id {
	case 0:
		res_data["id"] = "__x64_sys_bind_entry"

		res_data["Fd"] = event_data.Fd
		res_data["Backlog"] = event_data.Backlog

	case 1:
		res_data["id"] = "__x64_sys_bind_exit"

		res_data["return_value"] = event_data.Ret

	}

	return res_data, nil
}

// loads the ebpf specs like maps, programs
func getEbpfObject() (*listenObjects, error) {
	var bpfObj listenObjects
	err := loadListenObjects(&bpfObj, nil)
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}
