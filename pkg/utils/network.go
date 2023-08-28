// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

// Package utils provides utility functions for interpreting network-related data.
package utils

import (
	"strconv"
	"strings"
)

// NetworkData is an interface for different network-related data types.
type NetworkData interface {
	GetSaFamily() uint16    // Get the socket address family.
	InterpretPort() uint16  // Interpret the port number.
	GetIPv4Addr() uint32    // Get the IPv4 address.
	GetIPv6Addr() [16]uint8 // Get the IPv6 address.
	GetUnixAddr() [108]int8 // Get the Unix address.
}

// GetSocketDomainName returns the socket domain's name for the given domain value.
func GetSocketDomainName(domain interface{}) string {
	var value uint32

	switch d := domain.(type) {
	case uint32:
		value = d
	case uint16:
		value = uint32(d)
	default:
		return "UNKNOWN"
	}

	name, exists := socketDomains[value]
	if !exists {
		return "UNKNOWN"
	}
	return name
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

// Domain looks up the socket domain name based on the provided value.
func Domain(sd uint32) string {
	var res string

	if sdName, ok := socketDomains[sd]; ok {
		res = sdName
	} else {
		res = strconv.Itoa(int(sd))
	}

	return res
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

// Type converts the given socket type value to its string representation.
func Type(st uint32) string {
	var f []string

	if stName, ok := socketTypes[st&0xf]; ok {
		f = append(f, stName)
	} else {
		f = append(f, strconv.Itoa(int(st)))
	}

	// Check for special socket type flags
	if st&000004000 == 000004000 {
		f = append(f, "SOCK_NONBLOCK")
	}
	if st&002000000 == 002000000 {
		f = append(f, "SOCK_CLOEXEC")
	}

	return strings.Join(f, "|")
}

// protocols maps protocol values to their names.
var protocols = map[uint32]string{
	1:  "ICMP",
	6:  "TCP",
	17: "UDP",
	58: "ICMPv6",
}

// Protocol looks up the name of the given protocol value.
func Protocol(proto uint32) string {
	var res string

	if protoName, ok := protocols[proto]; ok {
		res = protoName
	} else {
		res = strconv.Itoa(int(proto))
	}

	return res
}

// HandlerFunc defines a function that handles specific network data.
type HandlerFunc func(NetworkData) (string, string)

// DefaultHandler is a default function to handle NetworkData.
func DefaultHandler(e NetworkData) (string, string) {
	familyName := GetSocketDomainName(e.GetSaFamily())
	if familyName == "UNKNOWN" {
		return strconv.Itoa(int(e.GetSaFamily())), "N/A"
	}
	return familyName, "N/A"
}

// HandleIPv4 handles IPv4-specific data.
func HandleIPv4(e NetworkData) (string, string) {
	return "AF_INET", ipv4ToString(e.GetIPv4Addr())
}

// HandleIPv6 handles IPv6-specific data.
func HandleIPv6(e NetworkData) (string, string) {
	return "AF_INET6", ipv6ToString(e.GetIPv6Addr())
}

// HandleUnix handles Unix-specific data.
func HandleUnix(e NetworkData) (string, string) {
	return "AF_UNIX", byteArrayToString(e.GetUnixAddr())
}

// keyFromValueCache caches the results of the getKeyFromValue function.
var keyFromValueCache = make(map[string]uint32)

// getKeyFromValue returns the key for a given value from the socketDomains map.
func getKeyFromValue(value string) uint32 {
	// Check cache first
	if key, exists := keyFromValueCache[value]; exists {
		return key
	}

	// Search for the key
	for k, v := range socketDomains {
		if v == value {
			keyFromValueCache[value] = k // Cache the result
			return k
		}
	}

	return 0
}

// FamilyHandlers is a map that associates socket families with their handlers.
var FamilyHandlers = map[uint32]HandlerFunc{
	getKeyFromValue("AF_INET"):  HandleIPv4,
	getKeyFromValue("AF_INET6"): HandleIPv6,
	getKeyFromValue("AF_UNIX"):  HandleUnix,
}

// InterpretFamilyAndIP interprets the family, IP, and port from the given network data.
func InterpretFamilyAndIP(e NetworkData) (family string, ip string, port uint16) {
	handler, exists := FamilyHandlers[uint32(e.GetSaFamily())]
	if !exists {
		handler = DefaultHandler
	}
	family, ip = handler(e)
	port = e.InterpretPort()
	return
}
