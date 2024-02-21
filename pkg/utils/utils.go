// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

// Package utils provides utility functions for the application.
package utils

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/intelops/tarian-detector/pkg/err"
)

var utilsErr = err.New("utils.utils")

// KernelVersion returns a combined version number(major.minor.patch) as integer
func KernelVersion(major, minor, patch int) int {
	// Ensure patch number does not exceed 255
	if patch > 255 {
		patch = 255
	}

	// Combine major, minor, and patch into a single integer
	return (major << 16) + (minor << 8) + patch
}

// CurrentKernelVersion returns current kernel version as an integer value
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

// PrintEvent prints the given data map along with a total captured count
// and a divider.
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
