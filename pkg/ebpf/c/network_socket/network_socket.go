package network_socket

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"fmt"
	"strconv"
	"strings"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -target $CURR_ARCH  -type event_data socket socket.bpf.c -- -I../../../../headers

func getEbpfObject() (*socketObjects, error) {
	var bpfObj socketObjects
	err := loadSocketObjects(&bpfObj, nil)
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}
// EntryEventData is the exported data from the eBPF struct counterpart
// The intention is to use the proper Go string instead of byte arrays from C.
// It makes it simpler to use and can generate proper json.
type SocketEventData struct {
	Domain   uint32
	Type     uint32
	Protocol int32
}

func newSocketEventDataFromEbpf(e socketEventData) *SocketEventData {
	evt := &SocketEventData{
		Domain:          e.Domain,
		Type:           e.Type,
		Protocol:       e.Protocol,

	}
	return evt
}


type NetworkSocketDetector struct {
	ebpfLink      link.Link
	perfReader *perf.Reader
}

func NewNetworkSocketDetector() *NetworkSocketDetector {
	return &NetworkSocketDetector{}
}

func (o *NetworkSocketDetector) Start() error {
	bpfObjs, err := getEbpfObject()
	if err != nil {
		return err
	}

	l, err := link.Kprobe("__x64_sys_socket", bpfObjs.KprobeSocket, nil)
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

func (o *NetworkSocketDetector) Close() error {
	err := o.ebpfLink.Close()
	if err != nil {
		return err
	}

	return o.perfReader.Close()
}

func (o *NetworkSocketDetector) Read() (*SocketEventData, error) {
	var ebpfEvent socketEventData
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


	exportedEvent := newSocketEventDataFromEbpf(ebpfEvent)
	return exportedEvent, nil
}

func (o *NetworkSocketDetector) ReadAsInterface() (any, error) {
	return o.Read()
}


func printToScreen(e socketEventData)  {
	fmt.Println("-----------------------------------------")
	fmt.Printf("Domain: %s\n", Domain(e.Domain))
	fmt.Printf("Type : %s\n", Type(e.Type))
	fmt.Printf("Protocol: %s\n", Protocol(e.Protocol))
	fmt.Println("-----------------------------------------")
}



func prompt(msg string) {
	fmt.Printf("\n%s \r", msg)
}

var socketDomains = map[uint32]string{
	0:  "AF_UNSPEC",
	1:  "AF_UNIX",
	2:  "AF_INET",
	3:  "AF_AX25",
	4:  "AF_IPX",
	5:  "AF_APPLETALK",
	6:  "AF_NETROM",
	7:  "AF_BRIDGE",
	8:  "AF_ATMPVC",
	9:  "AF_X25",
	10: "AF_INET6",
	11: "AF_ROSE",
	12: "AF_DECnet",
	13: "AF_NETBEUI",
	14: "AF_SECURITY",
	15: "AF_KEY",
	16: "AF_NETLINK",
	17: "AF_PACKET",
	18: "AF_ASH",
	19: "AF_ECONET",
	20: "AF_ATMSVC",
	21: "AF_RDS",
	22: "AF_SNA",
	23: "AF_IRDA",
	24: "AF_PPPOX",
	25: "AF_WANPIPE",
	26: "AF_LLC",
	27: "AF_IB",
	28: "AF_MPLS",
	29: "AF_CAN",
	30: "AF_TIPC",
	31: "AF_BLUETOOTH",
	32: "AF_IUCV",
	33: "AF_RXRPC",
	34: "AF_ISDN",
	35: "AF_PHONET",
	36: "AF_IEEE802154",
	37: "AF_CAIF",
	38: "AF_ALG",
	39: "AF_NFC",
	40: "AF_VSOCK",
	41: "AF_KCM",
	42: "AF_QIPCRTR",
	43: "AF_SMC",
	44: "AF_XDP",
}

// getSocketDomain Function
func Domain(sd uint32) string {
	// readSocketDomain prints the `domain` bitmask argument of the `socket` syscall
	// http://man7.org/linux/man-pages/man2/socket.2.html

	var res string

	if sdName, ok := socketDomains[sd]; ok {
		res = sdName
	} else {
		res = strconv.Itoa(int(sd))
	}

	return res
}

var socketTypes = map[uint32]string{
	1:  "SOCK_STREAM",
	2:  "SOCK_DGRAM",
	3:  "SOCK_RAW",
	4:  "SOCK_RDM",
	5:  "SOCK_SEQPACKET",
	6:  "SOCK_DCCP",
	10: "SOCK_PACKET",
}

func Type(st uint32) string {
	// readSocketType prints the `type` bitmask argument of the `socket` syscall
	// http://man7.org/linux/man-pages/man2/socket.2.html
	// https://elixir.bootlin.com/linux/v5.5.3/source/arch/mips/include/asm/socket.h

	var f []string

	if stName, ok := socketTypes[st&0xf]; ok {
		f = append(f, stName)
	} else {
		f = append(f, strconv.Itoa(int(st)))
	}
	if st&000004000 == 000004000 {
		f = append(f, "SOCK_NONBLOCK")
	}
	if st&002000000 == 002000000 {
		f = append(f, "SOCK_CLOEXEC")
	}

	return strings.Join(f, "|")
}

var protocols = map[int32]string{
	1:  "ICMP",
	6:  "TCP",
	17: "UDP",
	58: "ICMPv6",
}

// getProtocol Function
func Protocol(proto int32) string {
	var res string

	if protoName, ok := protocols[proto]; ok {
		res = protoName
	} else {
		res = strconv.Itoa(int(proto))
	}

	return res
}