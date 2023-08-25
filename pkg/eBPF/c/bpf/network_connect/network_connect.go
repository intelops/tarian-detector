// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package network_connect

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/bpf"
	"github.com/intelops/tarian-detector/pkg/utils"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data -target $CURR_ARCH  connect connect.bpf.c -- -I../../../../../headers -I../../

type NetworkConnect struct{}

func NewNetworkConnect() *NetworkConnect {
	return &NetworkConnect{}
}

func (e *connectEventData) GetSaFamily() uint16 {
    return e.SaFamily
}

func (e *connectEventData) InterpretPort() uint16 {
	return e.Port
}


func (e *connectEventData) GetIPv4Addr() uint32 {
    return e.V4Addr.S_addr
}

func (e *connectEventData) GetIPv6Addr() [16]uint8 {
    return e.V6Addr.S6Addr
}

func (e *connectEventData) GetUnixAddr() [108]int8 {
    return e.UnixAddr.Path
}


func (fo *NetworkConnect) NewModule() (bpf.BpfModule, error) {
	bm := bpf.NewBpfModule()

	bpfObjs, err := getEbpfObject()
	if err != nil {
		return bm, err
	}

	bm.Programs = []bpf.BpfProgram{
		{
			Id: "__x64_sys_connect_entry",
			Hook: bpf.Hook{
				Type: bpf.Kprobe,
				Name: "__x64_sys_connect",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Name:         bpfObjs.KprobeConnectEntry,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_connect_exit",
			Hook: bpf.Hook{
				Type: bpf.Kretprobe,
				Name: "__x64_sys_connect",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Name:         bpfObjs.KretprobeConnectExit,
			ShouldAttach: true,
		},
	}

	bm.Data = &connectEventData{}
	bm.Map = bpfObjs.Event
	bm.ParseData = parseData

	return bm, nil
}

func parseData(data any) (map[string]any, error) {
	event_data, ok := data.(*connectEventData)
	if !ok {
		return nil, fmt.Errorf("type mismatch: expected %T received %T", event_data, data)
	}

	res_data := utils.SetContext(event_data.EventContext)

	// event specific information
	switch event_data.Id {
	case 0:
		res_data["id"] = "__x64_sys_connect_entry"

		res_data["Fd"] = (event_data.Fd)
		family, ip, port := utils.InterpretFamilyAndIP(event_data)
		res_data["AddressFamily"] =  family
		res_data["IPAddress"] = ip
		res_data["Port"] = port
		res_data["Address length"] = event_data.Addrlen

	case 1:
		res_data["id"] = "__x64_sys_connect_exit"

		res_data["return_value"] = event_data.Ret

	}

	return res_data, nil
}

// loads the ebpf specs like maps, programs
func getEbpfObject() (*connectObjects, error) {
	var bpfObj connectObjects
	err := loadConnectObjects(&bpfObj, nil)
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}
