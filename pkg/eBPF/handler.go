// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package ebpf

import (
	"github.com/cilium/ebpf/link"
	"github.com/intelops/tarian-detector/pkg/err"
)

var handlerErr = err.New("ebpf.handler")

// Handler represents an eBPF handler. It includes the name of the handler, a list of map readers, and a list of probe links.
type Handler struct {
	name       string      // Name of the handler
	mapReaders []any       // List of map readers
	probeLinks []link.Link // List of probe links
}

// NewHandler creates a new eBPF handler with the given name.
func NewHandler(n string) *Handler {
	return &Handler{
		name:       n,
		mapReaders: nil,
		probeLinks: nil,
	}
}

// AddProbeLink adds a probe link to the handler.
func (h *Handler) AddProbeLink(l link.Link) {
	h.probeLinks = append(h.probeLinks, l)
}

// AddMapReaders adds map readers to the handler.
func (h *Handler) AddMapReaders(mrs []any) {
	h.mapReaders = append(h.mapReaders, mrs...)
}

// ReadAsInterface returns a slice of functions that read data from maps.
func (h *Handler) ReadAsInterface() ([]func() ([]byte, error), error) {
	return read(h.mapReaders)
}

// Count returns the number of probe links in the handler.
func (h *Handler) Count() int {
	return len(h.probeLinks)
}

// Close detaches probes and closes map readers.
func (h *Handler) Close() error {
	if err := detachProbes(h.probeLinks); err != nil {
		return handlerErr.Throwf("%v", err)
	}

	return closeMapReaders(h.mapReaders)
}

// GetName returns the name of the handler.
func (h *Handler) GetName() string {
	return h.name
}

// GetMapReaders returns the map readers associated with the handler.
func (h *Handler) GetMapReaders() []any {
	return h.mapReaders
}

// GetProbeLinks returns the probe links associated with the handler.
func (h *Handler) GetProbeLinks() []link.Link {
	return h.probeLinks
}
