// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

// Package network_socket manages operations related to network sockets with eBPF.
package network_socket

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/bpf"
	"github.com/intelops/tarian-detector/pkg/utils"
)

// This directive is used to generate code using bpf2go tool.
// It helps in generating Go bindings for the eBPF program defined in socket.bpf.c.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data -target $CURR_ARCH socket socket.bpf.c -- -I../../../../../headers -I../../

// NetworkSocket struct represents the eBPF based network socket operations.
type NetworkSocket struct{}

// NewNetworkSocket creates and returns a new instance of NetworkSocket.
func NewNetworkSocket() *NetworkSocket {
	return &NetworkSocket{}
}

// NewModule initializes and returns a new BpfModule which contains
// the eBPF programs and other related configurations for monitoring network socket events.
func (fo *NetworkSocket) NewModule() (bpf.BpfModule, error) {
	bm := bpf.NewBpfModule()

	// Load eBPF objects (programs, maps)
	bpfObjs, err := getEbpfObject()
	if err != nil {
		return bm, err
	}

	// Define eBPF programs for socket entry and exit events.
	bm.Programs = []bpf.BpfProgram{
		{
			Id: "__x64_sys_socket_entry",
			Hook: bpf.Hook{
				Type: bpf.Kprobe,
				Name: "__x64_sys_socket",
				Opts: &link.KprobeOptions{}, // Can be nil. Options for the kprobe hook.
			},
			Name:         bpfObjs.KprobeSocketEntry,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_socket_exit",
			Hook: bpf.Hook{
				Type: bpf.Kretprobe,
				Name: "__x64_sys_socket",
				Opts: &link.KprobeOptions{}, // Can be nil. Options for the kretprobe hook.
			},
			Name:         bpfObjs.KretprobeSocketExit,
			ShouldAttach: true,
		},
	}

	// Assign data structures and parsing functions.
	bm.Data = &socketEventData{}
	bm.Map = bpfObjs.SocketEventMap
	bm.ParseData = parseData

	return bm, nil
}

// parseData interprets the received eBPF event data, extracts necessary fields,
// and returns a map containing the parsed details.
func parseData(data any) (map[string]any, error) {
	event_data, ok := data.(*socketEventData)
	if !ok {
		return nil, fmt.Errorf("type mismatch: expected %T received %T", event_data, data)
	}

	// Get contextual information from the event data.
	res_data := utils.SetContext(event_data.EventContext)

	// Extract specific details based on the event type.
	switch event_data.Id {
	case 0:
		res_data["id"] = "__x64_sys_socket_entry"

		res_data["domain"] = utils.Domain(event_data.Domain)
		res_data["type"] = utils.Type(event_data.Type)
		res_data["protocol"] = utils.Protocol(event_data.Protocol)
	case 1:
		res_data["id"] = "__x64_sys_socket_exit"

		res_data["return_value"] = event_data.Ret
	}

	return res_data, nil
}

// getEbpfObject loads eBPF specs like maps, programs, etc.
// It returns the loaded eBPF objects.
func getEbpfObject() (*socketObjects, error) {
	var bpfObj socketObjects
	err := loadSocketObjects(&bpfObj, nil)
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}
