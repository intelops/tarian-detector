// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package utils

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
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
	return strings.Trim(string(arr[:]), "\x00")
}

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

// WriteJSONToFile appends a JSON object to a file in JSON array format
func WriteJSONToFile(data map[string]interface{}, filename string, mutex *sync.Mutex) error {
	mutex.Lock()
	defer mutex.Unlock()

	var objects []map[string]interface{}

	// Read existing JSON from the file, if it exists
	file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	err = json.NewDecoder(file).Decode(&objects)
	if err != nil && err.Error() != "EOF" {
		return err
	}

	// Append the new JSON object to the array
	objects = append(objects, data)

	// Write the updated JSON array to the file
	file.Seek(0, 0)
	file.Truncate(0)

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "   ")

	if err := encoder.Encode(objects); err != nil {
		return err
	}

	return nil
}
