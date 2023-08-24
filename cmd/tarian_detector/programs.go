// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package main

import (
	"github.com/intelops/tarian-detector/pkg/eBPF/c/bpf"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/bpf/file_close"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/bpf/file_open"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/bpf/file_openat"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/bpf/file_openat2"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/bpf/file_read"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/bpf/file_readv"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/bpf/file_write"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/bpf/file_writev"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/bpf/process_execve"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/bpf/process_execveat"
)

var BpfModules = []bpf.Module{
	process_execve.NewProcessExecve(),
	process_execveat.NewProcessExecveat(),
	file_open.NewFileOpen(),
	file_openat.NewFileOpenat(),
	file_openat2.NewFileOpenat2(),
	file_read.NewFileRead(),
	file_readv.NewFileReadv(),
	file_write.NewFileWrite(),
	file_writev.NewFileWritev(),
	file_close.NewFileClose(),
}
