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
	NotInClusterErrMsg string = "Kubernetes environment not detected. The Kubernetes context has been disabled."
)

func K8Watcher() (*k8s.PodWatcher, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, k8sErr.Throwf("%v", err)
	}

	clientSet := kubernetes.NewForConfigOrDie(config)
	watcher := k8s.NewPodWatcher(clientSet)

	return watcher, nil
}

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

func GetK8sContext(watcher *k8s.PodWatcher, processId uint32) (K8sContext, error) {
	k8sCtx := K8sContext{}

	if watcher == nil {
		return k8sCtx, k8sErr.Throw("kubernetes watcher is not enabled. This might not be the kubernetes environment.")
	}

	containerId, err := k8s.ProcsContainerID(processId)
	if err != nil {
		return k8sCtx, k8sErr.Throwf("%v", err)
	}

	if len(containerId) == 0 {
		return k8sCtx, k8sErr.Throw("missing container id")
	}

	pod := watcher.FindPod(containerId)
	if pod == nil {
		return k8sCtx, k8sErr.Throwf("unable to find the pod associated with the container ID: %s", containerId)
	}

	// pod information
	k8sCtx.PodUid = string(pod.ObjectMeta.UID)
	k8sCtx.PodName = pod.ObjectMeta.Name
	k8sCtx.PodGeneratedName = pod.ObjectMeta.GenerateName
	k8sCtx.PodKind = pod.Kind
	k8sCtx.PodAPIVersion = pod.APIVersion
	k8sCtx.PodLabels = pod.ObjectMeta.Labels
	k8sCtx.PodAnnotations = pod.ObjectMeta.Annotations

	// container information
	k8sCtx.ContainerID = containerId

	// namespace information
	k8sCtx.Namespace = pod.ObjectMeta.Namespace

	return k8sCtx, nil
}
