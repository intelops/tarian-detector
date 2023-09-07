// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package k8s

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	containerIdx   = "container-ids"
	containerIDLen = 15
)

var (
	errNotPod = errors.New("object is not a *corev1.Pod")
)

// containerIndexFunc index pod by container IDs.
func ContainerIndexFunc(obj interface{}) ([]string, error) {
	var containerIDs []string
	appendContainerID := func(fullContainerID string) error {
		if fullContainerID == "" {
			// This is expected if the container hasn't been started. This function
			// will get called again after the container starts, so we just need to
			// be patient.
			return nil
		}

		containerID, err := CleanContainerIDFromPod(fullContainerID)
		if err != nil {
			return err
		}

		containerIDs = append(containerIDs, containerID)

		return nil
	}

	switch t := obj.(type) {
	case *corev1.Pod:
		for _, container := range t.Status.InitContainerStatuses {
			err := appendContainerID(container.ContainerID)
			if err != nil {
				return nil, err
			}
		}
		for _, container := range t.Status.ContainerStatuses {
			err := appendContainerID(container.ContainerID)
			if err != nil {
				return nil, err
			}
		}
		for _, container := range t.Status.EphemeralContainerStatuses {
			err := appendContainerID(container.ContainerID)
			if err != nil {
				return nil, err
			}
		}
		return containerIDs, nil
	}
	return nil, fmt.Errorf("%w - found %T", errNotPod, obj)
}

func CleanContainerIDFromPod(podContainerID string) (string, error) {
	parts := strings.Split(podContainerID, "//")
	if len(parts) != 2 {
		return "", fmt.Errorf("unexpected containerID format, expecting 'docker://<name>', got %q", podContainerID)
	}

	containerID := parts[1]
	if len(containerID) > containerIDLen {
		containerID = containerID[:containerIDLen]
	}

	return containerID, nil
}

type K8sPodWatcher interface {
	FindPod(containerID string) *corev1.Pod
}

type PodWatcher struct {
	podInformer     cache.SharedIndexInformer
	informerFactory informers.SharedInformerFactory
}

func NewPodWatcher(k8sClient *kubernetes.Clientset) *PodWatcher {
	k8sInformerFactory := informers.NewSharedInformerFactory(k8sClient, 60*time.Second) // informers.WithTweakListOptions(func(options *metav1.ListOptions) {

	podInformer := k8sInformerFactory.Core().V1().Pods().Informer()
	err := podInformer.AddIndexers(map[string]cache.IndexFunc{
		containerIdx: ContainerIndexFunc,
	})
	if err != nil {
		log.Fatal(err)
	}

	return &PodWatcher{podInformer: podInformer, informerFactory: k8sInformerFactory}
}

func (watcher *PodWatcher) Start() {
	watcher.informerFactory.Start(wait.NeverStop)
	watcher.informerFactory.WaitForCacheSync(wait.NeverStop)

	// fmt.Println("PodWatcher: initial pods sync", "num", len(watcher.podInformer.GetStore().ListKeys()))
}

func (watcher *PodWatcher) FindPod(containerID string) *corev1.Pod {
	indexedContainerID := containerID
	if len(containerID) > containerIDLen {
		indexedContainerID = containerID[:containerIDLen]
	}

	pods, err := watcher.podInformer.GetIndexer().ByIndex(containerIdx, indexedContainerID)
	if err != nil {
		return nil
	}

	return FindContainer(containerID, pods)
}

func FindContainer(containerID string, pods []interface{}) *corev1.Pod {
	if containerID == "" {
		return nil
	}

	for _, obj := range pods {
		pod, ok := obj.(*corev1.Pod)
		if !ok {
			return nil
		}

		for _, container := range pod.Status.ContainerStatuses {
			if ContainerIDContains(container.ContainerID, containerID) {
				return pod
			}
		}
		for _, container := range pod.Status.InitContainerStatuses {
			if ContainerIDContains(container.ContainerID, containerID) {
				return pod
			}
		}
		for _, container := range pod.Status.EphemeralContainerStatuses {
			if ContainerIDContains(container.ContainerID, containerID) {
				return pod
			}
		}
	}

	return nil
}

func ContainerIDContains(containerID string, prefix string) bool {
	parts := strings.Split(containerID, "//")
	if len(parts) == 2 && strings.HasPrefix(parts[1], prefix) {
		return true
	}

	return false
}
