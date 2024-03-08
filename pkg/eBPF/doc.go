// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

// Package ebpf provides a high-level API for managing and interacting with eBPF (Extended Berkeley Packet Filter) programs and maps in the Linux kernel.
// It includes structures and functions for creating, managing, and interacting with eBPF programs and maps.
//
// The package is designed to be used with the github.com/cilium/ebpf library and includes support for various eBPF features such as ring buffers, perf events, and arrays of maps.
// It provides the ability to create new eBPF programs, attach them to hooks, and retrieve information about them.
//
// The package also provides the ability to create and manage eBPF maps, including ring buffer maps, perf event array maps, and arrays of maps.
// It provides functions for creating readers for these maps, reading data from them, and closing the readers when they are no longer needed.
//
// Additionally, the package provides structures and functions for working with eBPF hooks, including the ability to attach eBPF programs to hooks and detach them.
package ebpf
