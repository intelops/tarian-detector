// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package utils

import (
	"fmt"
	"net"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// converts [][4096]uint8 to string.
func Uint8ArrtoString(arr [][4096]uint8) string {
	var res_str string

	for _, el := range arr {
		temp := Uint8toString(el[:])
		if len(temp) == 0 {
			continue
		}

		if res_str != "" {
			res_str += " " + temp
		} else {
			res_str += temp
		}
	}

	return res_str
}

// converts [][4096]uint8 to []string.
func Uint8ArrtoStringArr(arr [][4096]uint8) []string {
	var res_arr_str []string
	for _, el := range arr {
		temp := Uint8toString(el[:])
		if len(temp) == 0 {
			continue
		}

		res_arr_str = append(res_arr_str, temp)
	}

	return res_arr_str
}

// converts []uint8 to string
func Uint8toString(arr []uint8) string {
	return unix.ByteSliceToString(arr[:])
}

// converts time in nanoseconds to readable time format
func NanoSecToTimeFormat(t uint64) string {
	return time.Unix(0, int64(time.Duration(t)*time.Nanosecond)).String()
}

// converts time in miliseconds to readable time format
func MiliSecToTimeFormat(t uint64) string {
	return time.Unix(int64(time.Duration(t)*time.Millisecond), 0).String()
}

// Convert IPv4 address from binary to string.
func ipv4ToString(addr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(addr), byte(addr>>8), byte(addr>>16), byte(addr>>24))
}

// Convert IPv6 address from binary to string.
func ipv6ToString(addr [16]uint8) string {
	return net.IP(addr[:]).String()
}

// byteArrayToString takes an array of int8 values, and converts it to a string.
func byteArrayToString(b [108]int8) string {
	return strings.TrimRight(string((*[108]byte)(unsafe.Pointer(&b))[:]), "\x00")
}

func Domain(sd uint32) string {
	return mapLookup(socketDomains, sd)
}

func Type(st uint32) string {
	return mapLookup(socketTypes, st&0xf, st&SOCK_NONBLOCK, st&SOCK_CLOEXEC)
}

func Protocol(proto uint32) string {
	return mapLookup(protocols, proto)
}

func DefaultHandler(e NetworkData) (string, string) {
	return Domain(uint32(e.GetSaFamily())), "N/A"
}

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