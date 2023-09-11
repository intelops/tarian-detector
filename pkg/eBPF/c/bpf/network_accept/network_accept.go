// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package network_accept

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/bpf"
	"github.com/intelops/tarian-detector/pkg/utils"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data -target $CURR_ARCH  accept accept.bpf.c -- -I../../../../../headers -I../../

type NetworkAccept struct{}

func NewNetworkAccept() *NetworkAccept {
	return &NetworkAccept{}
}

func (fo *NetworkAccept) NewModule() (bpf.BpfModule, error) {
	bm := bpf.NewBpfModule()

	bpfObjs, err := getEbpfObject()
	if err != nil {
		return bm, err
	}

	bm.Programs = []bpf.BpfProgram{
		{
			Id: "__x64_sys_accept_entry",
			Hook: bpf.Hook{
				Type: bpf.Kprobe,
				Name: "__x64_sys_accept",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Name:         bpfObjs.KprobeAcceptEntry,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_accept_exit",
			Hook: bpf.Hook{
				Type: bpf.Kretprobe,
				Name: "__x64_sys_accept",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Name:         bpfObjs.KretprobeAcceptExit,
			ShouldAttach: true,
		},
	}

	bm.Data = &acceptEventData{}
	bm.Map = bpfObjs.AcceptEventMap
	bm.ParseData = parseData

	return bm, nil
}

func parseData(data any) (map[string]any, error) {
	event_data, ok := data.(*acceptEventData)
	if !ok {
		return nil, fmt.Errorf("type mismatch: expected %T received %T", event_data, data)
	}

	res_data := utils.SetContext(event_data.EventContext)
	res_data["tarian_detector"] = "network_accept"

	// event specific information
	switch event_data.Id {
	case 0:
		res_data["tarian_detector_hook"] = "__x64_sys_accept_entry"

		res_data["fd"] = (event_data.Fd)

		family, ip, port := utils.InterpretFamilyAndIP(event_data.SaFamily, event_data.V4Addr.S_addr, event_data.V6Addr.S6Addr, event_data.UnixAddr.Path[:], event_data.Port)
		res_data["address_family"] = family
		res_data["ip_address"] = ip
		res_data["port"] = port

	case 1:
		res_data["tarian_detector_hook"] = "__x64_sys_accept_exit"

		res_data["return_value"] = event_data.Ret
	}

	return res_data, nil
}

// loads the ebpf specs like maps, programs
func getEbpfObject() (*acceptObjects, error) {
	var bpfObj acceptObjects
	err := loadAcceptObjects(&bpfObj, nil)
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}
