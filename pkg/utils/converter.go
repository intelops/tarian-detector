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
	// ErrOutOfBound represents an error for when a position is out of range for data of a certain length.
	ErrOutOfBound string = "index out of bounds: startIndex=%d, dataLength=%d"
)

// Int8 returns the int8 value at the specified position in the byte slice.
// It returns an error if the position is out of bounds or if there are not enough bytes left in the slice.
func Int8(b []byte, pos int) (int8, error) {
	if pos < 0 || pos >= len(b) {
		return 0, converterErr.Throwf(ErrOutOfBound, pos, len(b))
	}

	return int8(b[pos]), nil
}

// Int16 reads 2 bytes from the byte slice b starting at position pos and returns the int16 value.
// It returns an error if the position is out of bounds or if there are not enough bytes left in the slice.
func Int16(b []byte, pos int) (int16, error) {
	if pos < 0 || pos+2 > len(b) {
		return 0, converterErr.Throwf(ErrOutOfBound, pos, len(b))
	}

	return int16(binary.LittleEndian.Uint16(b[pos : pos+2])), nil
}

// Int32 reads 4 bytes from the byte slice b starting at the position pos and returns the int32 value.
// It returns an error if the position is out of bounds or if there are not enough bytes left in the slice.
func Int32(b []byte, pos int) (int32, error) {
	if pos < 0 || pos+4 > len(b) {
		return 0, converterErr.Throwf(ErrOutOfBound, pos, len(b))
	}

	return int32(binary.LittleEndian.Uint32(b[pos : pos+4])), nil
}

// Int64 reads 8 bytes from the byte slice b starting at the position pos and returns the int64 value.
// It returns an error if the position is out of bounds or if there are not enough bytes left in the slice.
func Int64(b []byte, pos int) (int64, error) {
	if pos < 0 || pos+8 > len(b) {
		return 0, converterErr.Throwf(ErrOutOfBound, pos, len(b))
	}

	return int64(binary.LittleEndian.Uint64(b[pos : pos+8])), nil
}

// Uint8 returns the uint8 value at the specified position in the byte slice.
// It returns an error if the position is out of bounds or if there are not enough bytes left in the slice.
func Uint8(b []byte, pos int) (uint8, error) {
	if pos < 0 || pos >= len(b) {
		return 0, converterErr.Throwf(ErrOutOfBound, pos, len(b))
	}

	return uint8(b[pos]), nil
}

// Uint16 reads 2 bytes from the byte slice b starting at the position pos and returns the uint16 value.
// It returns an error if the position is out of bounds or if there are not enough bytes left in the slice.
func Uint16(b []byte, pos int) (uint16, error) {
	if pos < 0 || pos+2 > len(b) {
		return 0, converterErr.Throwf(ErrOutOfBound, pos, len(b))
	}

	return binary.LittleEndian.Uint16(b[pos : pos+2]), nil
}

// Uint32 reads 4 bytes from the byte slice b starting at the position pos and returns uint32 value.
// It returns an error if the position is out of bounds or if there are not enough bytes
func Uint32(b []byte, pos int) (uint32, error) {
	if pos < 0 || pos+4 > len(b) {
		return 0, converterErr.Throwf(ErrOutOfBound, pos, len(b))
	}

	return binary.LittleEndian.Uint32(b[pos : pos+4]), nil
}

// Uint64 reads 8 bytes from the byte slice b starting at the position pos and returns uint64 value.
// It returns an error if the position is out of bounds or if there are not enough bytes
func Uint64(b []byte, pos int) (uint64, error) {
	if pos < 0 || pos+8 > len(b) {
		return 0, converterErr.Throwf(ErrOutOfBound, pos, len(b))
	}

	return binary.LittleEndian.Uint64(b[pos : pos+8]), nil
}

// ToString reads size bytes from the byte slice b starting at the position pos and converts it to a string and trims null characters.
// It returns an empty string if the position is out of bounds or if there are not enough bytes
func ToString(b []byte, pos int, size int) string {
	if pos < 0 || pos+size > len(b) {
		return ""
	}

	return strings.Trim(string(b[pos:pos+size]), "\x00")
}

// Ipv4 reads 4 bytes from a byte slice b starting at the position pos and converts it to an IPv4 string
// It returns an empty string if the position is out of bounds or if there are not enough bytes
func Ipv4(b []byte, pos int) string {
	if pos < 0 || pos+4 > len(b) {
		return ""
	}

	return net.IP(b[pos : pos+4]).String()
}

// Ipv6 reads 16 bytes from a byte slice b starting at the position pos and converts it to an IPv6 string
// It returns an empty string if the position is out of bounds or if there are not enough bytes
func Ipv6(b []byte, pos int) string {
	if pos < 0 || pos+16 > len(b) {
		return ""
	}

	return net.IP(b[pos : pos+16]).String()
}

// Ntohs converts a little-endian uint16 value to a big-endian uint16 value and returns the result.
func Ntohs(n uint16) uint16 {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, n)

	return binary.BigEndian.Uint16(b)
}
