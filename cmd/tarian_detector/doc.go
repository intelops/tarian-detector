// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

// Package main provides the Tarian detector application.
//
// The application sets up the necessary components such as the Kubernetes watcher, the eBPF module,
// and the event detectors, and starts the main event loop. It listens for interrupt signals (Ctrl+C or SIGTERM)
// and gracefully shuts down when one is received. It also continuously reads events from the detectors and
// retrieves the Kubernetes context based on the host process ID.
//
// The package uses the Kubernetes client-go library to interact with the Kubernetes API server. It retrieves
// the Kubernetes context for a given process by finding the pod associated with the container ID of the process.
// The Kubernetes context includes information about the pod, the container, and the namespace.
package main
