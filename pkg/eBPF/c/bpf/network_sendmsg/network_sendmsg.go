// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package network_sendmsg

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/bpf"
	"github.com/intelops/tarian-detector/pkg/utils"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data -target $CURR_ARCH  sendmsg sendmsg.bpf.c -- -I../../../../../headers -I../../

type NetworkSendmsg struct{}

func NewNetworkSendmsg() *NetworkSendmsg {
	return &NetworkSendmsg{}
}

func (fo *NetworkSendmsg) NewModule() (bpf.BpfModule, error) {
	bm := bpf.NewBpfModule()

	bpfObjs, err := getEbpfObject()
	if err != nil {
		return bm, err
	}

	bm.Programs = []bpf.BpfProgram{
		{
			Id: "__x64_sys_sendmsg_entry",
			Hook: bpf.Hook{
				Type: bpf.Kprobe,
				Name: "__x64_sys_sendmsg",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Name:         bpfObjs.KprobeSendmsgEntry,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_sendmsg_exit",
			Hook: bpf.Hook{
				Type: bpf.Kretprobe,
				Name: "__x64_sys_sendmsg",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Name:         bpfObjs.KretprobeSendmsgExit,
			ShouldAttach: true,
		},
	}

	bm.Data = &sendmsgEventData{}
	bm.Map = bpfObjs.SendmsgEventMap
	bm.ParseData = parseData

	return bm, nil
}

func parseData(data any) (map[string]any, error) {
	event_data, ok := data.(*sendmsgEventData)
	if !ok {
		return nil, fmt.Errorf("type mismatch: expected %T received %T", event_data, data)
	}

	res_data := utils.SetContext(event_data.EventContext)

	// event specific information
	switch event_data.Id {
	case 0:
		res_data["id"] = "__x64_sys_sendmsg_entry"

		res_data["socket_file_descriptor"] = event_data.Fd
		res_data["message_length"] = event_data.Len //The length of the message being sent.
		res_data["flags"] = utils.ParseSendmsgFlags(event_data.Flags)
		res_data["Destination_address_length"] = event_data.MsgNamelen                                      //Length of the destination address in bytes.
		res_data["Destination_address"] = utils.InterpretMsgName(event_data.MsgName, event_data.MsgNamelen) //Destination address

	case 1:
		res_data["id"] = "__x64_sys_sendmsg_exit"

		res_data["return_value"] = event_data.Ret

	}

	return res_data, nil
}

// loads the ebpf specs like maps, programs
func getEbpfObject() (*sendmsgObjects, error) {
	var bpfObj sendmsgObjects
	err := loadSendmsgObjects(&bpfObj, nil)
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}
