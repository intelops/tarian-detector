// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package utils

import (
	"encoding/binary"
	"net"
	"strings"

	"github.com/intelops/tarian-detector/pkg/err"
)

var converterErr = err.New("utils.converter")

const (
	ErrOutOfBound string = "position %d out of range for data of length %d"
)

func Int8(b []byte, pos int) (int8, error) {
	if pos < 0 || pos >= len(b) {
		return 0, converterErr.Throwf(ErrOutOfBound, pos, len(b))
	}

	return int8(b[pos]), nil
}

func Int16(b []byte, pos int) (int16, error) {
	if pos < 0 || pos+2 > len(b) {
		return 0, converterErr.Throwf(ErrOutOfBound, pos, len(b))
	}

	return int16(binary.LittleEndian.Uint16(b[pos : pos+2])), nil
}

func Int32(b []byte, pos int) (int32, error) {
	if pos < 0 || pos+2 > len(b) {
		return 0, converterErr.Throwf(ErrOutOfBound, pos, len(b))
	}

	return int32(binary.LittleEndian.Uint32(b[pos : pos+4])), nil
}

func Int64(b []byte, pos int) (int64, error) {
	if pos < 0 || pos+2 > len(b) {
		return 0, converterErr.Throwf(ErrOutOfBound, pos, len(b))
	}

	return int64(binary.LittleEndian.Uint64(b[pos : pos+8])), nil
}

func Uint8(b []byte, pos int) (uint8, error) {
	if pos < 0 || pos >= len(b) {
		return 0, converterErr.Throwf(ErrOutOfBound, pos, len(b))
	}

	return uint8(b[pos]), nil
}

func Uint16(b []byte, pos int) (uint16, error) {
	if pos < 0 || pos+2 > len(b) {
		return 0, converterErr.Throwf(ErrOutOfBound, pos, len(b))
	}

	return binary.LittleEndian.Uint16(b[pos : pos+2]), nil
}

func Uint32(b []byte, pos int) (uint32, error) {
	if pos < 0 || pos+4 > len(b) {
		return 0, converterErr.Throwf(ErrOutOfBound, pos, len(b))
	}

	return binary.LittleEndian.Uint32(b[pos : pos+4]), nil
}

func Uint64(b []byte, pos int) (uint64, error) {
	if pos < 0 || pos+8 > len(b) {
		return 0, converterErr.Throwf(ErrOutOfBound, pos, len(b))
	}

	return binary.LittleEndian.Uint64(b[pos : pos+8]), nil
}

func ToString(b []byte, pos int, size int) string {
	if pos < 0 || pos+size > len(b) {
		return ""
	}

	return strings.Trim(string(b[pos:pos+size]), "\x00")
}

// Ipv4 converts a byte array to an IPv4 string
func Ipv4(b []byte, pos int) string {
	if pos < 0 || pos+4 > len(b) {
		return ""
	}

	return net.IP(b[pos : pos+4]).String()
}

// Ipv6 converts byte array to IPv6 string
func Ipv6(b []byte, pos int) string {
	if pos < 0 || pos+16 > len(b) {
		return ""
	}

	return net.IP(b[pos : pos+16]).String()
}

// Ntohs converts little-endian uint16 to big-endian uint16
func Ntohs(n uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, n)

	return binary.BigEndian.Uint16(b)
}
