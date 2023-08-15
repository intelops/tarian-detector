// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian
package network_bind

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -target $CURR_ARCH  -type event_data bind bind.bpf.c -- -I../../../../headers

// getEbpfObject loads the eBPF objects and returns a pointer to the bindObjects structure.
func getEbpfObject() (*bindObjects, error) {
	var bpfObj bindObjects
	err := loadBindObjects(&bpfObj, nil)
	// Return any error that occurs during loading.
	if err != nil {
		return nil, err
	}

	return &bpfObj, nil
}

// BindEventData represents the data received from the eBPF program.
// BindEventData is the exported data from the eBPF struct counterpart
// The intention is to use the proper Go string instead of byte arrays from C.
// It makes it simpler to use and can generate proper json.
type BindEventData struct {
	Pid      uint32
	Tgid     uint32
	Uid      uint32
	Gid      uint32
	Fd       int32
	SaFamily uint16
	Port     uint16
	V4Addr   struct{ S_addr uint32 }
	V6Addr   struct{ S6Addr [16]uint8 }
	UnixAddr struct{ Path [108]int8 }
	Padding2 uint32
	Addrlen  int32
}

// newBindEventDataFromEbpf creates a new BindEventData instance from the given eBPF data.
func newBindEventDataFromEbpf(e bindEventData) *BindEventData {
	evt := &BindEventData{
		Pid:       e.Pid,
		Tgid:      e.Tgid,
		Uid:       e.Uid,
		Gid:       e.Gid,
		Fd:        e.Fd,
		Addrlen:   e.Addrlen,
		Port:      e.Port,		
		SaFamily:  e.SaFamily,
		V4Addr:    e.V4Addr,
		V6Addr:    e.V6Addr,
		UnixAddr:  e.UnixAddr,
	}
	return evt
}

// NetworkBindDetector represents the detector for network bind events using eBPF.
type NetworkBindDetector struct {
	ebpfLink   link.Link
	ringbufReader *ringbuf.Reader
}

// NewNetworkBindDetector creates a new instance of NetworkBindDetector.
func NewNetworkBindDetector() *NetworkBindDetector {
	return &NetworkBindDetector{}
}

// Start initializes the NetworkBindDetector and starts monitoring network bind events.
func (o *NetworkBindDetector) Start() error {
	bpfObjs, err := getEbpfObject()
	// Return any error that occurs during loading.
	if err != nil {
		return err
	}

	l, err := link.Kprobe("__x64_sys_bind", bpfObjs.KprobeBind, nil)
	// Return any error that occurs during creating the Kprobe link.
	if err != nil {
		return err
	}

	o.ebpfLink = l
	rd, err := ringbuf.NewReader(bpfObjs.Event)

	// Return any error that occurs during creating the  event reader.
	if err != nil {
		return err
	}

	o.ringbufReader = rd
	return nil
}

// Close stops the NetworkBindDetector and closes associated resources.
func (o *NetworkBindDetector) Close() error {
	err := o.ebpfLink.Close()
	// Return any error that occurs during closing the link.
	if err != nil {
		return err
	}

	return o.ringbufReader.Close()
}

// Read retrieves the BindEventData from the eBPF program.
func (o *NetworkBindDetector) Read() (*BindEventData, error) {
	var ebpfEvent bindEventData
	record, err := o.ringbufReader.Read()
	// Return any error that occurs during reading from the  event reader.
	if err != nil {
		// If the  reader is closed, return the error as is.
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, err
		}
		return nil, err
	}

	// Read the raw sample from the record using binary.Read.
	if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &ebpfEvent); err != nil {
		return nil, err
	}
	exportedEvent := newBindEventDataFromEbpf(ebpfEvent)
	return exportedEvent, nil
}

// ReadAsInterface implements the ReadAsInterface method of the ebpf.Exporter interface.
// It calls the Read method internally.
func (o *NetworkBindDetector) ReadAsInterface() (any, error) {
	return o.Read()
}

func ipv4ToString(addr uint32) string {
    return fmt.Sprintf("%d.%d.%d.%d", byte(addr), byte(addr>>8), byte(addr>>16), byte(addr>>24))
}

// Convert IPv6 address from binary to string.
func ipv6ToString(addr [16]uint8) string {
    b := make([]byte, 16)
    for i := 0; i < 4; i++ {
        val := binary.BigEndian.Uint32(addr[i*4 : (i+1)*4])
        binary.BigEndian.PutUint32(b[i*4:], val)
    }
    return net.IP(b).String()
}

func byteArrayToString(b [108]int8) string {
    return strings.TrimRight(string((*[108]byte)(unsafe.Pointer(&b))[:]), "\x00")
}

func (e *BindEventData) InterpretPort() uint16 {
 return e.Port
}

type HandlerFunc func(*BindEventData) (string, string)

var families = map[uint16]string{
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

func defaultHandler(e *BindEventData) (string, string) {
    familyName, exists := families[e.SaFamily]
    if !exists {
        familyName = "UNKNOWN"
    }
    return familyName, "N/A"
}

func handleIPv4(e *BindEventData) (string, string) {
    return "AF_INET", ipv4ToString(e.V4Addr.S_addr)
}

func handleIPv6(e *BindEventData) (string, string) {
    return "AF_INET6", ipv6ToString(e.V6Addr.S6Addr)
}

func handleUnix(e *BindEventData) (string, string) {
    return "AF_UNIX", byteArrayToString(e.UnixAddr.Path)
}

var familyHandlers = map[int]HandlerFunc{
    AF_INET:   handleIPv4,
    AF_INET6:  handleIPv6,
    AF_UNIX:   handleUnix,
}

func (e *BindEventData) InterpretFamilyAndIP() (family string, ip string, port uint16) {
	handler, exists := familyHandlers[int(e.SaFamily)]
    if !exists {
        handler = defaultHandler
    }
    family, ip = handler(e)
    port = e.InterpretPort()
    return
}

