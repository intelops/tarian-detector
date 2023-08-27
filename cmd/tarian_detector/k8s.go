// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package main

import (
	"github.com/intelops/tarian-detector/pkg/k8s"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func K8Watcher() (*k8s.PodWatcher, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	client := kubernetes.NewForConfigOrDie(config)
	watcher := k8s.NewPodWatcher(client)

	return watcher, nil
}
