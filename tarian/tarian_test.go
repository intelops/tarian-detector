// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package tarian

import (
	"fmt"
	"os"
	"testing"

	ebpf "github.com/intelops/tarian-detector/pkg/eBPF"
)

func setup(major, minor, patch any) {
	os.Setenv("LINUX_VERSION_MAJOR", fmt.Sprintf("%v", major))
	os.Setenv("LINUX_VERSION_MINOR", fmt.Sprintf("%v", minor))
	os.Setenv("LINUX_VERSION_PATCH", fmt.Sprintf("%v", patch))
}

func teardown() {
	os.Unsetenv("LINUX_VERSION_MAJOR")
	os.Unsetenv("LINUX_VERSION_MINOR")
	os.Unsetenv("LINUX_VERSION_PATCH")
}

// TestGetModule_Probe_count tests the GetModule function with a specific probe count.
func TestGetModule_Probe_count(t *testing.T) {
	setup(5, 8, 0)
	got, err := GetModule()

	if err != nil {
		t.Errorf("GetModule() error = %v", err)
	}

	probeCount := 16 * 2
	if len(got.GetPrograms()) != probeCount {
		t.Errorf("GetModule() = %v, want %v", len(got.GetPrograms()), probeCount)
	}

	teardown()
}

// TestGetModule_Perf_Check tests the GetModule function for the map type PerfEventArray
func TestGetModule_Perf_Check(t *testing.T) {
	setup(5, 6, 0)
	got, err := GetModule()

	if err != nil {
		t.Errorf("GetModule() error = %v", err)
	}

	if got.GetMap().GetMapType() != ebpf.PerfEventArray {
		t.Errorf("GetModule().ebpfMap = %v, want %v", got.GetMap().GetMapType(), ebpf.PerfEventArray)
	}

	teardown()
}

// TestGetModule_Ring_Check tests the GetModule function for the map type PerfEventArray
func TestGetModule_Ring_Check(t *testing.T) {
	setup(5, 19, 0)
	got, err := GetModule()

	if err != nil {
		t.Errorf("GetModule() error = %v", err)
	}

	// this is intended to be a perf event as we are currently only supporting perf events
	// once we were able to create an array ring buffer directly then we would need to change this test
	if got.GetMap().GetMapType() != ebpf.PerfEventArray {
		t.Errorf("GetModule().ebpfMap = %v, want %v", got.GetMap().GetMapType(), ebpf.PerfEventArray)
	}

	teardown()
}

// TestGetModule_Kernel_Version_Err tests the GetModule function with invalid arguments
func TestGetModule_Kernel_Version_Err(t *testing.T) {
	setup("ab", "cd", "ef") // invalid arguments

	_, err := GetModule()

	if err == nil {
		t.Errorf("GetModule() error = %v, wantErr %v", err, "true")

	}

	teardown()
}
