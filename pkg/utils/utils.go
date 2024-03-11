// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package utils

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/intelops/tarian-detector/pkg/err"
)

var utilsErr = err.New("utils.utils")

// KernelVersion combines the major, minor, and patch version numbers into a single integer.
// It ensures that the patch number does not exceed 255. If it does, the patch number is set to 255.
// The function returns the combined version number.
func KernelVersion(major, minor, patch int) int {
	// Ensure patch number does not exceed 255
	if patch > 255 {
		patch = 255
	}

	// Combine major, minor, and patch into a single integer
	return (major << 16) + (minor << 8) + patch
}

// CurrentKernelVersion retrieves the current kernel version from environment variables.
// It returns an error if the required environment variables are not set or if they cannot be converted to integers.
func CurrentKernelVersion() (int, error) {
	const (
		envNotFound string = "unable to check the kernel version, LINUX_VERSION_MAJOR, LINUX_VERSION_MINOR, LINUX_VERSION_PATCH must be defined"
	)

	// Get environment variables
	major, minor, patch := os.Getenv("LINUX_VERSION_MAJOR"), os.Getenv("LINUX_VERSION_MINOR"), os.Getenv("LINUX_VERSION_PATCH")
	// Check if environment variables are not set
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

// PrintEvent prints the given data map along with a total captured count and a divider.
// It uses a predefined set of keys to extract values from the data map.
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
