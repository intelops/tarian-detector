// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package main

import (
	"github.com/intelops/tarian-detector/pkg/detector"
	"github.com/intelops/tarian-detector/pkg/eBPF/c/bpf"
	"github.com/intelops/tarian-detector/pkg/linker"
)

// attaches the ebpf programs to kernel and returns the refrences of maps and link.
func LoadPrograms(modules []bpf.Module) (*linker.Linker, error) {
	linker := linker.NewLinker()

	for _, module := range modules {
		bpfModule, err := module.NewModule()
		if err != nil {
			return linker, err
		}

		linker.Attach(bpfModule)
	}

	return linker, nil
}

func GetDetectors(handlers []*linker.Handler) ([]detector.EventDetector, error) {
	detectors := make([]detector.EventDetector, 0)

	for _, handler := range handlers {
		detectors = append(detectors, handler)
	}

	return detectors, nil
}
