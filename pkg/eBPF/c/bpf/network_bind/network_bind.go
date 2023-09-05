// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package network_bind

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/bpf"
	"github.com/intelops/tarian-detector/pkg/utils"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data -target $CURR_ARCH bind bind.bpf.c -- -I../../../../../headers -I../../

// NetworkBind is an empty struct that serves as a receiver for methods related to network bindings.
type NetworkBind struct{}

// NewNetworkBind creates and returns a new instance of NetworkBind.
func NewNetworkBind() *NetworkBind {
	return &NetworkBind{}
}

// GetSaFamily returns the socket address family.
func (e *bindEventData) GetSaFamily() uint16 {
	return e.SaFamily
}

// InterpretPort returns the port from the event data.
func (e *bindEventData) InterpretPort() uint16 {
	return e.Port
}

// GetIPv4Addr extracts and returns the IPv4 address from the event data.
func (e *bindEventData) GetIPv4Addr() uint32 {
	return e.V4Addr.S_addr
}

// GetIPv6Addr extracts and returns the IPv6 address from the event data.
func (e *bindEventData) GetIPv6Addr() [16]uint8 {
	return e.V6Addr.S6Addr
}

// GetUnixAddr extracts and returns the Unix address from the event data.
func (e *bindEventData) GetUnixAddr() []uint8 {
	return e.UnixAddr.Path[:]
}

// NewModule initializes a new BPF module for network binding and attaches necessary eBPF programs.
func (fo *NetworkBind) NewModule() (bpf.BpfModule, error) {
	bm := bpf.NewBpfModule()

	bpfObjs, err := getEbpfObject()
	if err != nil {
		return bm, err
	}

	bm.Programs = []bpf.BpfProgram{
		{
			Id: "__x64_sys_bind_entry",
			Hook: bpf.Hook{
				Type: bpf.Kprobe,
				Name: "__x64_sys_bind",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Name:         bpfObjs.KprobeBindEntry,
			ShouldAttach: true,
		},
		{
			Id: "__x64_sys_bind_exit",
			Hook: bpf.Hook{
				Type: bpf.Kretprobe,
				Name: "__x64_sys_bind",
				Opts: &link.KprobeOptions{}, //can be nil
			},
			Name:         bpfObjs.KretprobeBindExit,
			ShouldAttach: true,
		},
	}

	bm.Data = &bindEventData{}
	bm.Map = bpfObjs.BindEventMap
	bm.ParseData = parseData

	return bm, nil
}

func parseData(data any) (map[string]any, error) {
	event_data, ok := data.(*bindEventData)
	if !ok {
		return nil, fmt.Errorf("type mismatch: expected %T received %T", event_data, data)
	}

	res_data := utils.SetContext(event_data.EventContext)

	// event specific information
	switch event_data.Id {
	case 0:
		res_data["tarian_detector"] = "__x64_sys_bind_entry"

		res_data["fd"] = (event_data.Fd)

		family, ip, port := utils.InterpretFamilyAndIP(event_data)
		res_data["address_family"] = family
		res_data["ip_address"] = ip
		res_data["port"] = port

		res_data["address_length"] = event_data.Addrlen

	case 1:
		res_data["tarian_detector"] = "__x64_sys_bind_exit"

		res_data["return_value"] = event_data.Ret

	}

	return res_data, nil
}

// loads the ebpf specs like maps, programs
func getEbpfObject() (*bindObjects, error) {
	var bpfObj bindObjects
	err := loadBindObjects(&bpfObj, nil)
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}
