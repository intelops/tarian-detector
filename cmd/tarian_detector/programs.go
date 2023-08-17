// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package main

import (
	"github.com/intelops/tarian-detector/pkg/eBPF/c/BPF/file_close"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/BPF/file_open"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/BPF/file_openat"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/BPF/file_openat2"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/BPF/file_read"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/BPF/file_readv"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/BPF/file_write"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/BPF/file_writev"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/BPF/process_execve"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/BPF/process_execveat"
	"github.com/intelops/tarian-detector/pkg/inspector/detector"
	"github.com/intelops/tarian-detector/pkg/inspector/ebpf_manager"
)

// attaches the ebpf programs to kernel and returns the refrences of maps and link.
func getEbpfDetectors() ([]detector.EventDetector, error) {

	//holds reference to all ebpf programs
	var ebpf_programs = []ebpf_manager.EbpfProgram{
		process_execve.NewExecve(),
		process_execveat.NewExecveat(),
		file_read.NewRead(),
		file_readv.NewReadv(),
		file_write.NewFileWrite(),
		file_writev.NewFileWritev(),
		file_open.NewFileOpen(),
		file_openat.NewFileOpenat(),
		file_openat2.NewFileOpenat2(),
		file_close.NewClose(),
	}

	eBPFPrograms := ebpf_manager.NewEbpfPrograms()
	for _, program := range ebpf_programs {
		eBPFPrograms.Add(program)
	}

	return eBPFPrograms.LoadPrograms()
}
