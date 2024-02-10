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

// converts time in nanoseconds to readable time format
func NanoSecToTimeFormat(t uint64) string {
	return time.Unix(0, int64(time.Duration(t)*time.Nanosecond)).String()
}

// converts time in miliseconds to readable time format
func MiliSecToTimeFormat(t uint64) string {
	return time.Unix(int64(time.Duration(t)*time.Millisecond), 0).String()
}

func KernelVersion(a, b, c int) int {
	if c > 255 {
		c = 255
	}

	return (a << 16) + (b << 8) + c
}

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

func Ipv4(b [4]byte) string {
	return net.IP(b[:]).String()
}

func Ipv6(b [16]byte) string {
	return net.IP(b[:]).String()
}

func Ntohs(n uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, n)

	return binary.BigEndian.Uint16(b)
}
