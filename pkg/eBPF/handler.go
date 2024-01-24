// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package ebpf

import (
	"github.com/cilium/ebpf/link"
	"github.com/intelops/tarian-detector/pkg/err"
)

type Handler struct {
	name       string
	mapReaders []any
	probeLinks []link.Link
}

var handlerErr = err.New("ebpf.Handler")

func NewHandler(n string) *Handler {
	return &Handler{
		name:       n,
		mapReaders: nil,
		probeLinks: nil,
	}
}

func (h *Handler) AddProbeLink(l link.Link) {
	h.probeLinks = append(h.probeLinks, l)
}

func (h *Handler) AddMapReaders(mrs []any) {
	h.mapReaders = append(h.mapReaders, mrs...)
}

func (h *Handler) ReadAsInterface() ([]func() ([]byte, error), error) {
	return read(h.mapReaders)
}

func (h *Handler) Close() error {
	if err := detachProbes(h.probeLinks); err != nil {
		return handlerErr.Throwf("%v", err)
	}

	return closeMapReaders(h.mapReaders)
}
