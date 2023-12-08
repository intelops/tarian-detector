// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package ebpf

import (
	"github.com/cilium/ebpf/link"
	"github.com/intelops/tarian-detector/pkg/err"
)

type Handler struct {
	Name       string
	MapReaders []any
	ProbeLinks []link.Link
}

var handlerErr = err.New("ebpf.Handler")

func NewHandler(n string) *Handler {
	return &Handler{
		Name:       n,
		MapReaders: nil,
		ProbeLinks: nil,
	}
}

func (h *Handler) AddProbeLink(l link.Link) {
	h.ProbeLinks = append(h.ProbeLinks, l)
}

func (h *Handler) AddMapReaders(mrs []any) {
	h.MapReaders = append(h.MapReaders, mrs...)
}

func (h *Handler) ReadAsInterface() ([]func() ([]byte, error), error) {
	return read(h.MapReaders)
}

func (h *Handler) Close() error {
	if err := detachProbes(h.ProbeLinks); err != nil {
		return handlerErr.Throwf("%v", err)
	}

	return closeMapReaders(h.MapReaders)
}
