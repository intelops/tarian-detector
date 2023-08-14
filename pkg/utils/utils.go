// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package utils

import (
	"fmt"
	"time"
)

// converts [256][4096]uint8 to string.
func Uint8ArrtoString(arr [256][4096]uint8) string {
	var res_str string = ""

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

// converts [256][4096]uint8 to []string.
func Uint8ArrtoStringArr(arr [256][4096]uint8) []string {
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
	return fmt.Sprintf("%s", removeNullBytes(arr)[:])
}

// converts time in nanoseconds to readable time format
func NanoSecToTimeFormat(t uint64) string {
	return time.Unix(0, int64(time.Duration(t)*time.Nanosecond)).String()
}

// converts time in miliseconds to readable time format
func MiliSecToTimeFormat(t uint64) string {
	return time.Unix(int64(time.Duration(t)*time.Millisecond), 0).String()
}

// removes null bytes from []uint8.
func removeNullBytes(arr []uint8) []uint8 {
	idx := indexOf(arr, 0)
	return arr[:idx]
}

// returns the index of first occurence of element in the array
func indexOf(arr []uint8, val uint8) int {
	for idx, ele := range arr {
		if ele == val {
			return idx
		}
	}

	return -1
}
