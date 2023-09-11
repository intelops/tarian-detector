// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

// Package utils provides utility functions for interpreting network-related data.
package utils

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	SOCK_NONBLOCK = 000004000
	SOCK_CLOEXEC  = 002000000
	AF_INET       = 2
	AF_INET6      = 10
	AF_UNIX       = 1
)

// Utility function to get string representation or fallback to numeric value
func MapLookup(m map[uint32]string, key uint32, additionalFlags ...uint32) string {
	var f []string
	if name, ok := m[key]; ok {
		f = append(f, name)
	} else {
		f = append(f, strconv.Itoa(int(key)))
	}
	for _, flag := range additionalFlags {
		if name, ok := m[flag]; ok {
			f = append(f, name)
		}
	}
	return strings.Join(f, "|")
}

// socketDomains contains the mapping of socket domain values to their corresponding names.
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

// socketTypes maps socket type values to their respective names.
var socketTypes = map[uint32]string{
	1:  "SOCK_STREAM",
	2:  "SOCK_DGRAM",
	3:  "SOCK_RAW",
	4:  "SOCK_RDM",
	5:  "SOCK_SEQPACKET",
	6:  "SOCK_DCCP",
	10: "SOCK_PACKET",
}

// protocols maps protocol values to their names.
var protocols = map[uint32]string{
	1:  "ICMP",
	6:  "TCP",
	17: "UDP",
	58: "ICMPv6",
}

var sendmsgFlags = map[uint32]string{
	1:          "MSG_OOB",       // Sends out-of-band data on sockets that support this notion (e.g., of type SOCK_STREAM); the underlying protocol must also support out-of-band data.
	2:          "MSG_PEEK",      // Peek at incoming messages.
	4:          "MSG_DONTROUTE", // Don't use a gateway to send out the packet, send to hosts only on directly connected networks. This is usually used only by diagnostic or routing programs.
	8:          "MSG_CTRUNC",    // Control data lost before delivery.
	16:         "MSG_PROXY",     // Supply or ask for a second address.
	32:         "MSG_TRUNC",     // Truncate message if it's too long.
	64:         "MSG_DONTWAIT",  // Enables nonblocking operation; if the operation would block, EAGAIN or EWOULDBLOCK is returned.
	128:        "MSG_EOR",       // Terminates a record (when this notion is supported, as for sockets of type SOCK_SEQPACKET).
	256:        "MSG_WAITALL",   // Wait for a full request.
	512:        "MSG_FIN",
	1024:       "MSG_SYN",
	2048:       "MSG_CONFIRM", // Tell the link layer that forward progress happened.
	4096:       "MSG_RST",
	8192:       "MSG_ERRQUEUE",     // Fetch message from the error queue.
	16384:      "MSG_NOSIGNAL",     // Don't generate a SIGPIPE signal if the peer on a stream-oriented socket has closed the connection.
	32768:      "MSG_MORE",         // The caller has more data to send.
	65536:      "MSG_WAITFORONE",   // Wait for at least one packet to return.
	262144:     "MSG_BATCH",        // More messages coming (used with sendmmsg).
	67108864:   "MSG_ZEROCOPY",     // Use user data in the kernel path.
	536870912:  "MSG_FASTOPEN",     // Send data in TCP SYN.
	1073741824: "MSG_CMSG_CLOEXEC", // Set close_on_exit for file descriptor received through SCM_RIGHTS.
}

// HandlerFunc defines a function that handles specific network data.
type HandlerFunc func(saFamily uint16, v4Addr uint32, v6Addr [16]uint8, unixAddr []uint8, port uint16) (string, string)

var familyHandlers = map[int]HandlerFunc{
	AF_INET:  HandleIPv4,
	AF_INET6: HandleIPv6,
	AF_UNIX:  HandleUnix,
}

// Convert IPv4 address from binary to string.
func Ipv4ToString(addr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(addr), byte(addr>>8), byte(addr>>16), byte(addr>>24))
}

// Convert IPv6 address from binary to string.
func Ipv6ToString(addr [16]uint8) string {
	return net.IP(addr[:]).String()
}

func Domain(sd uint32) string {
	return MapLookup(socketDomains, sd)
}

func Type(st uint32) string {
	return MapLookup(socketTypes, st&0xf, st&SOCK_NONBLOCK, st&SOCK_CLOEXEC)
}

func Protocol(proto uint32) string {
	return MapLookup(protocols, proto)
}

func InterpretPort(port uint16) uint16 {
	return port
}

func DefaultHandler(saFamily uint16, v4Addr uint32, v6Addr [16]uint8, unixAddr []uint8, port uint16) (string, string) {
	familyName, exists := socketDomains[uint32(saFamily)]
	if !exists {
		familyName = "UNKNOWN"
	}
	return familyName, "N/A"
}

func HandleIPv4(saFamily uint16, v4Addr uint32, v6Addr [16]uint8, unixAddr []uint8, port uint16) (string, string) {
	return "AF_INET", Ipv4ToString(v4Addr)
}

// HandleIPv6 handles IPv6-specific data.
func HandleIPv6(saFamily uint16, v4Addr uint32, v6Addr [16]uint8, unixAddr []uint8, port uint16) (string, string) {
	return "AF_INET6", Ipv6ToString(v6Addr)
}

// HandleUnix handles Unix-specific data.
func HandleUnix(saFamily uint16, v4Addr uint32, v6Addr [16]uint8, unixAddr []uint8, port uint16) (string, string) {
	return "AF_UNIX", Uint8toString(unixAddr)
}

// ParseSendmsgFlags parses sendmsg flag values to their string representation.
func ParseSendmsgFlags(flags uint32) string {
    var parsedFlags []string
    for bit, name := range sendmsgFlags {
        if flags&bit != 0 {
            parsedFlags = append(parsedFlags, name)
            flags &= ^bit // Remove this flag bit from the remaining flags
        }
    }

    // Add any remaining unrecognized flags as numeric values.
    if flags != 0 {
        parsedFlags = append(parsedFlags, strconv.FormatUint(uint64(flags), 16))
    }

    return strings.Join(parsedFlags, "|")
}

// InterpretFamilyAndIP interprets the family, IP, and port from the given network data.
func InterpretFamilyAndIP(saFamily uint16, v4Addr uint32, v6Addr [16]uint8, unixAddr []uint8, port uint16) (family string, ip string, retPort uint16) {
	handler, exists := familyHandlers[int(saFamily)]
	if !exists {
		handler = DefaultHandler
	}
	family, ip = handler(saFamily, v4Addr, v6Addr, unixAddr, port)
	retPort = InterpretPort(port)
	return
}

// InterpretMsgName interprets msg_name to its correct form based on its address family.
// Takes in msgName which is the array containing the address, and msgLen which is the length of the address.
func InterpretMsgName(msgName [64]uint8, msgLen int32) string {
	// If msg_namelen is zero, the message will be sent to an address that the kernel already knows about
	if msgLen == 0 {
		return "Destination is implied (msg_namelen is zero)"
	}

	// Assuming first two bytes represent the address family in little endian
	saFamily := binary.LittleEndian.Uint16(msgName[:2])

	var v4Addr uint32
	var v6Addr [16]uint8
	var unixAddr []uint8

	switch saFamily {
	case AF_INET: // AF_INET for IPv4
		v4Addr = binary.LittleEndian.Uint32(msgName[4:8])
	case AF_INET6: // AF_INET6 for IPv6
		copy(v6Addr[:], msgName[8:24])
	case AF_UNIX: // AF_UNIX for Unix Domain Socket
		// Extracting until the first null byte as AF_UNIX addresses are usually null-terminated
		for _, b := range msgName[2:msgLen] { // Start from index 2 to skip the family bytes
			if b == 0 {
				break
			}
			unixAddr = append(unixAddr, b)
		}
	}

	handler, exists := familyHandlers[int(saFamily)]
	if !exists {
		handler = DefaultHandler
	}

	_, ip := handler(saFamily, v4Addr, v6Addr, unixAddr, 0) // Passing 0 for port as it's not used here

	if saFamily == AF_UNIX {
		return "Unix: " + ip
	}

	return ip
}
