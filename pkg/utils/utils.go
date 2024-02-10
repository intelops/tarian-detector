// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package utils

import (
	"encoding/binary"
	"net"
	"os"
	"strconv"
	"time"
)

// NanoSecToTimeFormat converts time in nanoseconds to time string
func NanoSecToTimeFormat(t uint64) string {
	return time.Unix(0, int64(time.Duration(t)*time.Nanosecond)).String()
}

// MiliSecToTimeFormat converts time in miliseconds to time string
func MiliSecToTimeFormat(t uint64) string {
	return time.Unix(int64(time.Duration(t)*time.Millisecond), 0).String()
}

// KernelVersion returns a combined version number(major.minor.patch) as integer
func KernelVersion(a, b, c int) int {
	if c > 255 {
		c = 255
	}

	return (a << 16) + (b << 8) + c
}

// CurrentKernelVersion returns current kernel version as an integer value
func CurrentKernelVersion() (int, error) {
	a, err := strconv.Atoi(os.Getenv("LINUX_VERSION_MAJOR"))
	if err != nil {
		return 0, err
	}

	b, err := strconv.Atoi(os.Getenv("LINUX_VERSION_MINOR"))
	if err != nil {
		return 0, err
	}

	c, err := strconv.Atoi(os.Getenv("LINUX_VERSION_PATCH"))
	if err != nil {
		return 0, err
	}

	return KernelVersion(a, b, c), nil
}

// Ipv4 converts a byte array to an IPv4 string
func Ipv4(b [4]byte) string {
	return net.IP(b[:]).String()
}

// Ipv6 converts byte array to IPv6 string
func Ipv6(b [16]byte) string {
	return net.IP(b[:]).String()
}

// Ntohs converts little-endian uint16 to big-endian uint16
func Ntohs(n uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, n)

	return binary.BigEndian.Uint16(b)
}
