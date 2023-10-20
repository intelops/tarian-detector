// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package utils

import (
	"bytes"
	"encoding/binary"
	"strings"
)

func Int(b []byte) (int32, error) {
	var num int32
	err := binary.Read(bytes.NewReader(b), binary.LittleEndian, &num)
	if err != nil {
		return num, err
	}

	return num, nil
}

func Int64(b []byte) (int64, error) {
	var num int64
	err := binary.Read(bytes.NewReader(b), binary.LittleEndian, &num)
	if err != nil {
		return num, err
	}

	return num, nil
}

func Uint16(b []byte) (uint16, error) {
	var num uint16
	err := binary.Read(bytes.NewReader(b), binary.LittleEndian, &num)
	if err != nil {
		return num, err
	}

	return num, nil
}

func Uint(b []byte) (uint32, error) {
	var num uint32
	err := binary.Read(bytes.NewReader(b), binary.LittleEndian, &num)
	if err != nil {
		return num, err
	}

	return num, nil
}

func Uint64(b []byte) (uint64, error) {
	var num uint64
	err := binary.Read(bytes.NewReader(b), binary.LittleEndian, &num)
	if err != nil {
		return num, err
	}

	return num, nil
}

func ToString(arr []byte) string {
	return strings.Trim(string(arr[:]), "\x00")
}
