// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package main

import (
	"github.com/intelops/tarian-detector/pkg/err"
	"github.com/intelops/tarian-detector/pkg/k8s"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var k8sErr = err.New("main.k8s")

const (
	// NotInClusterErrMsg is an error message for when the Kubernetes environment is not detected.
	NotInClusterErrMsg string = "Kubernetes environment not detected. The Kubernetes context has been disabled."
)

// K8Watcher initializes and returns a new PodWatcher for the current Kubernetes cluster.
func K8Watcher() (*k8s.PodWatcher, error) {
	// Get the in-cluster configuration.
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, k8sErr.Throwf("%v. %s", err, NotInClusterErrMsg)
	}

	// Create a new Kubernetes client set.
	clientSet := kubernetes.NewForConfigOrDie(config)

	// Return a new PodWatcher for the current Kubernetes cluster.
	return k8s.NewPodWatcher(clientSet)
}

// K8sContext holds the Kubernetes context for a given process.
type K8sContext struct {
	// pod information
	PodUid           string
	PodName          string
	PodGeneratedName string
	PodKind          string
	PodAPIVersion    string
	PodLabels        map[string]string
	PodAnnotations   map[string]string

	// container information
	ContainerID string

	// namespace information
	Namespace string
}

// GetK8sContext returns the Kubernetes context for a given process ID.
func GetK8sContext(watcher *k8s.PodWatcher, processId uint32) (K8sContext, error) {
	k8sCtx := K8sContext{}

	if watcher == nil {
		return k8sCtx, k8sErr.Throw("kubernetes watcher is not enabled. This might not be the kubernetes environment.")
	}

	// Get the container ID for the given process ID.
	containerId, err := k8s.ProcsContainerID(processId)
	if err != nil {
		return k8sCtx, k8sErr.Throwf("%v", err)
	}

	// If the container ID is missing, return an error.
	if len(containerId) == 0 {
		return k8sCtx, k8sErr.Throw("missing container id")
	}

	// Find the pod associated with the container ID.
	pod, err := watcher.FindPod(containerId)
	if err != nil {
		return k8sCtx, k8sErr.Throwf("%v: unable to find the pod associated with the container ID: %s", err, containerId)
	}

	// Set the pod information in the Kubernetes context.
	k8sCtx.PodUid = string(pod.ObjectMeta.UID)
	k8sCtx.PodName = pod.ObjectMeta.Name
	k8sCtx.PodGeneratedName = pod.ObjectMeta.GenerateName
	k8sCtx.PodKind = pod.Kind
	k8sCtx.PodAPIVersion = pod.APIVersion
	k8sCtx.PodLabels = pod.ObjectMeta.Labels
	k8sCtx.PodAnnotations = pod.ObjectMeta.Annotations

	// Set the container information in the Kubernetes context.
	k8sCtx.ContainerID = containerId

	// Set the namespace information in the Kubernetes context.
	k8sCtx.Namespace = pod.ObjectMeta.Namespace

	return k8sCtx, nil
}
