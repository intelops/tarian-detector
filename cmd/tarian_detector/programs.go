// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package main

import (
	"github.com/intelops/tarian-detector/pkg/eBPF/c/BPF/process_entry"
	"github.com/intelops/tarian-detector/pkg/inspector/detector"
	"github.com/intelops/tarian-detector/pkg/inspector/ebpf_manager"
)

// attaches the ebpf programs to kernel and returns the refrences of maps and link.
func getEbpfPrograms() ([]detector.EventDetector, error) {

	//holds reference to all ebpf programs
	var ebpf_programs = []ebpf_manager.EbpfProgram{
		process_entry.NewProcessEntryEbpf(),
	}

	eBPFPrograms := ebpf_manager.NewEbpfProgram()
	for _, program := range ebpf_programs {
		eBPFPrograms.Add(program)
	}

	return eBPFPrograms.LoadPrograms()
}
