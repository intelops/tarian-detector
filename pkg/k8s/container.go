// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package k8s

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/intelops/tarian-detector/pkg/err"
)

var containerErr = err.New("k8s.container")

const (
	// ContainerIDLength is the standard length of the Container ID
	ContainerIDLength = 64

	// BpfContainerIDLength Minimum 31 chars to assume it is a Container ID
	// in case it was truncated
	BpfContainerIDLength = 31

	// DockerIDLength is the length of a Docker container ID.
	DockerIDLength = 128

	// HostProcDir is the directory where host process information is stored.
	HostProcDir = "/host/proc"
)

// ProcsContainerID returns the container ID for a given process ID (pid).
// It reads the cgroup file for the process and extracts the container ID from it.
// If an error occurs during this process, it is returned.
func ProcsContainerID(pid uint32) (string, error) {
	pidstr := fmt.Sprint(pid)
	cgroups, err := os.ReadFile(filepath.Join(HostProcDir, pidstr, "cgroup"))

	if err != nil {
		return "", containerErr.Throwf("%v", err)
	}

	containerID := FindDockerIDFromCgroup(string(cgroups))
	return containerID, nil
}

// FindDockerIDFromCgroup extracts the Docker container ID from a cgroup string.
// It does this by splitting the cgroup string into paths, and checking each path
// for the presence of a Docker container ID. If a valid ID is found, it is returned.
func FindDockerIDFromCgroup(cgroups string) string {
	cgrpPaths := strings.Split(cgroups, "\n")
	for _, s := range cgrpPaths {
		if strings.Contains(s, "pod") || strings.Contains(s, "docker") ||
			strings.Contains(s, "libpod") {
			// Get the container ID and the offset
			container := LookupContainerID(s)
			if container != "" {
				return container
			}
		}
	}
	return ""
}

// ProcsContainerIDOffset Returns the container ID and its offset
// This can fail, better use LookupContainerId to handle different container runtimes.
func ProcsContainerIDOffset(subdir string) (string, int) {
	// If the cgroup subdir contains ":" it means that we are dealing with
	// Linux.CgroupPath where the cgroup driver is cgroupfs
	// https://github.com/opencontainers/runc/blob/main/docs/systemd.md
	// In this case let's split the name and take the last one
	p := strings.LastIndex(subdir, ":") + 1
	fields := strings.Split(subdir, ":")
	idStr := fields[len(fields)-1]

	off := strings.LastIndex(idStr, "-") + 1
	s := strings.Split(idStr, "-")

	return s[len(s)-1], off + p
}

// LookupContainerID returns the container ID as a 31 character string length from the full cgroup path
// cgroup argument is the full cgroup path
// Returns the container ID as a string of 31 characters and its offset on the full cgroup path,
// otherwise on errors an empty string and 0 as offset.
func LookupContainerID(cgroup string) string {
	subDirs := strings.Split(cgroup, "/")
	lastSubDir := subDirs[len(subDirs)-1]

	container, _ := ProcsContainerIDOffset(lastSubDir)

	if len(container) >= BpfContainerIDLength {
		return container[:BpfContainerIDLength]
	}

	return ""
}
