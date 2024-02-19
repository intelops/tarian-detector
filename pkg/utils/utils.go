// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package utils

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/intelops/tarian-detector/pkg/err"
)

var utilsErr = err.New("utils.utils")

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
	const (
		envNotFound string = "unable to check the kernel version, LINUX_VERSION_MAJOR, LINUX_VERSION_MINOR, LINUX_VERSION_PATCH must be defined"
	)

	major, minor, patch := os.Getenv("LINUX_VERSION_MAJOR"), os.Getenv("LINUX_VERSION_MINOR"), os.Getenv("LINUX_VERSION_PATCH")
	if len(major) == 0 || len(minor) == 0 || len(patch) == 0 {
		return 0, utilsErr.Throw(envNotFound)
	}

	a, err := strconv.Atoi(major)
	if err != nil {
		return 0, utilsErr.Throwf("%v", err)
	}

	b, err := strconv.Atoi(minor)
	if err != nil {
		return 0, utilsErr.Throwf("%v", err)
	}

	c, err := strconv.Atoi(patch)
	if err != nil {
		return 0, utilsErr.Throwf("%v", err)
	}

	return KernelVersion(a, b, c), nil
}

func PrintEvent(data map[string]any, t int) {
	keys := []string{
		"eventId", "timestamp", "syscallId", "processor",
		"threadStartTime", "hostProcessId", "hostThreadId",
		"hostParentProcessId", "processId", "threadId", "parentProcessId",
		"userId", "groupId", "cgroupId", "mountNamespace", "pidNamespace",
		"execId", "parentExecId", "processName", "directory",
		"sysname", "nodename", "release", "version", "machine", "domainname",
		"context",
	}
	div := "=================================="
	msg := ""
	for _, ky := range keys {
		msg += fmt.Sprintf("%s: %+v\n", ky, data[ky])
	}

	log.Printf("Total captured %d.\n%s\n%s%s\n", t, div, msg, div)
}
