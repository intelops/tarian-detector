// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian
package network_bind

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"

	"fmt"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -target $CURR_ARCH  -type event_data bind bind.bpf.c -- -I../../../../headers
func getEbpfObject() (*bindObjects, error) {
	var bpfObj bindObjects
	err := loadBindObjects(&bpfObj, nil)
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}

// BindEventData is the exported data from the eBPF struct counterpart
// The intention is to use the proper Go string instead of byte arrays from C.
// It makes it simpler to use and can generate proper json.
type BindEventData struct {
	Args [3]uint64
}

func newBindEventDataFromEbpf(e bindEventData) *BindEventData {
	evt := &BindEventData{
		Args: [3]uint64{
			e.Args[0],
			e.Args[1],
			e.Args[2],
		},
	}
	return evt
}

type NetworkBindDetector struct {
	ebpfLink   link.Link
	perfReader *perf.Reader
}

func NewNetworkBindDetector() *NetworkBindDetector {
	return &NetworkBindDetector{}
}

func (o *NetworkBindDetector) Start() error {
	bpfObjs, err := getEbpfObject()
	if err != nil {
		return err
	}

	l, err := link.Kprobe("__x64_sys_bind", bpfObjs.KprobeBind, nil)
	if err != nil {
		return err
	}

	o.ebpfLink = l
	rd, err := perf.NewReader(bpfObjs.Event, os.Getpagesize())

	if err != nil {
		return err
	}

	o.perfReader = rd
	return nil
}

func (o *NetworkBindDetector) Close() error {
	err := o.ebpfLink.Close()
	if err != nil {
		return err
	}

	return o.perfReader.Close()
}

func (o *NetworkBindDetector) Read() (*BindEventData, error) {
	var ebpfEvent bindEventData
	record, err := o.perfReader.Read()
	if err != nil {
		if errors.Is(err, perf.ErrClosed) {
			return nil, err
		}
		return nil, err
	}

	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &ebpfEvent); err != nil {
		return nil, err
	}

	printToScreen(ebpfEvent)

	exportedEvent := newBindEventDataFromEbpf(ebpfEvent)
	return exportedEvent, nil
}

func (o *NetworkBindDetector) ReadAsInterface() (any, error) {
	return o.Read()
}

func printToScreen(e bindEventData) {
	fmt.Println("-----------------------------------------")
	fmt.Printf("Bind_File_descriptor: %d\n", e.Args[0])
	fmt.Printf("Bind_address : %s\n", IPv6(e.Args[1]))

	fmt.Println("-----------------------------------------")
}

func IP(in uint32) string {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, in)
	return ip.String()
}

func IPv6(in uint64) string {

	ip := make(net.IP, net.IPv6len)
	binary.BigEndian.PutUint64(ip, in)
	return ip.String()
}
