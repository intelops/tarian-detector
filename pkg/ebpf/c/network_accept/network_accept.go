package network_accept

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"

	"os"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -target $CURR_ARCH  -type event_data accept accept.bpf.c -- -I../../../../headers
func getEbpfObject() (*acceptObjects, error) {
	var bpfObj acceptObjects
	err := loadAcceptObjects(&bpfObj, nil)
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}
// AcceptEventData is the exported data from the eBPF struct counterpart
// The intention is to use the proper Go string instead of byte arrays from C.
// It makes it simpler to use and can generate proper json.
type AcceptEventData struct {
	Args[3]   uint64

}

func newAcceptEventDataFromEbpf(e acceptEventData) *AcceptEventData {
	evt := &AcceptEventData{
		Args: [3]uint64{
			e.Args[0],
			e.Args[1],
			e.Args[2],
	},
}
	return evt
}


type NetworkAcceptDetector struct {
	ebpfLink      link.Link
	perfReader *perf.Reader
}

func NewNetworkAcceptDetector() *NetworkAcceptDetector {
	return &NetworkAcceptDetector{}
}

func (o *NetworkAcceptDetector) Start() error {
	bpfObjs, err := getEbpfObject()
	if err != nil {
		return err
	}

	l, err := link.Kprobe("__x64_sys_accept", bpfObjs.KprobeAccept, nil)
	if err != nil {
		return err
	}

	o.ebpfLink = l
	rd, err := perf.NewReader(bpfObjs.Event,os.Getpagesize())

	if err != nil {
		return err
	}

	o.perfReader = rd
	return nil
}

func (o *NetworkAcceptDetector) Close() error {
	err := o.ebpfLink.Close()
	if err != nil {
		return err
	}

	return o.perfReader.Close()
}

func (o *NetworkAcceptDetector) Read() (*AcceptEventData, error) {
	var ebpfEvent acceptEventData
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


	exportedEvent := newAcceptEventDataFromEbpf(ebpfEvent)
	return exportedEvent, nil
}

func (o *NetworkAcceptDetector) ReadAsInterface() (any, error) {
	return o.Read()
}


func printToScreen(e acceptEventData)  {
	fmt.Println("-----------------------------------------")
	fmt.Printf("Accept_File_descriptor: %d\n", e.Args[0])
	fmt.Printf("Accept_address : %s\n", IPv6(e.Args[1]))

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
