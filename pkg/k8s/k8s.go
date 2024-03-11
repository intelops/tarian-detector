// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package k8s

import (
	"strings"
	"time"

	"github.com/intelops/tarian-detector/pkg/err"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

var k8sErr = err.New("k8s.k8s")

const (
	containerIdx   = "container-ids"
	containerIDLen = 15
)

// ContainerIndexFunc index pod by container IDs.
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
			return k8sErr.Throwf("%v", err)
		}

		containerIDs = append(containerIDs, containerID)

		return nil
	}

	t, ok := obj.(*corev1.Pod)
	if !ok {
		return nil, k8sErr.Throwf("object is not a *corev1.Pod - found %T", obj)
	}

	for _, container := range t.Status.InitContainerStatuses {
		err := appendContainerID(container.ContainerID)
		if err != nil {
			return nil, k8sErr.Throwf("%v", err)
		}
	}

	for _, container := range t.Status.ContainerStatuses {
		err := appendContainerID(container.ContainerID)
		if err != nil {
			return nil, k8sErr.Throwf("%v", err)
		}
	}

	for _, container := range t.Status.EphemeralContainerStatuses {
		err := appendContainerID(container.ContainerID)
		if err != nil {
			return nil, k8sErr.Throwf("%v", err)
		}
	}

	return containerIDs, nil
}

// CleanContainerIDFromPod cleans the full container ID from a pod to get the actual container ID.
func CleanContainerIDFromPod(podContainerID string) (string, error) {
	parts := strings.Split(podContainerID, "//")
	if len(parts) != 2 {
		return "", k8sErr.Throwf("unexpected containerID format, expecting 'docker://<name>', got %q", podContainerID)
	}

	containerID := parts[1]
	if len(containerID) > containerIDLen {
		containerID = containerID[:containerIDLen]
	}

	return containerID, nil
}

// K8sPodWatcher is an interface that defines the FindPod method.
type K8sPodWatcher interface {
	FindPod(containerID string) *corev1.Pod
}

// PodWatcher is a struct that implements the K8sPodWatcher interface.
type PodWatcher struct {
	podInformer     cache.SharedIndexInformer
	informerFactory informers.SharedInformerFactory
}

// NewPodWatcher creates a new PodWatcher.
func NewPodWatcher(k8sClient *kubernetes.Clientset) (*PodWatcher, error) {
	k8sInformerFactory := informers.NewSharedInformerFactory(k8sClient, 60*time.Second) // informers.WithTweakListOptions(func(options *metav1.ListOptions) {

	podInformer := k8sInformerFactory.Core().V1().Pods().Informer()
	err := podInformer.AddIndexers(map[string]cache.IndexFunc{
		containerIdx: ContainerIndexFunc,
	})
	if err != nil {
		return nil, k8sErr.Throwf("%v", err)
	}

	return &PodWatcher{podInformer: podInformer, informerFactory: k8sInformerFactory}, nil
}

// Start starts the PodWatcher.
func (watcher *PodWatcher) Start() {
	watcher.informerFactory.Start(wait.NeverStop)
	watcher.informerFactory.WaitForCacheSync(wait.NeverStop)
}

// FindPod finds a pod by its container ID.
func (watcher *PodWatcher) FindPod(containerID string) (*corev1.Pod, error) {
	indexedContainerID := containerID
	if len(containerID) > containerIDLen {
		indexedContainerID = containerID[:containerIDLen]
	}

	pods, err := watcher.podInformer.GetIndexer().ByIndex(containerIdx, indexedContainerID)
	if err != nil {
		return nil, k8sErr.Throwf("%v", err)
	}

	return FindContainer(containerID, pods)
}

// FindContainer searches through a list of pods for a container with the specified ID.
// It checks each container in each pod and returns the first pod that contains the specified container.
// If no such container is found in any known pod, it returns an error.
func FindContainer(containerID string, pods []interface{}) (*corev1.Pod, error) {
	if containerID == "" {
		return nil, k8sErr.Throw("missing container id")
	}

	for _, obj := range pods {
		pod, ok := obj.(*corev1.Pod)
		if !ok {
			return nil, k8sErr.Throwf("obj is not of type *corev1.Pod: %T", obj)
		}

		for _, container := range pod.Status.ContainerStatuses {
			if ContainerIDContains(container.ContainerID, containerID) {
				return pod, nil
			}
		}
		for _, container := range pod.Status.InitContainerStatuses {
			if ContainerIDContains(container.ContainerID, containerID) {
				return pod, nil
			}
		}
		for _, container := range pod.Status.EphemeralContainerStatuses {
			if ContainerIDContains(container.ContainerID, containerID) {
				return pod, nil
			}
		}
	}

	return nil, k8sErr.Throw("no such container in any known Pod")
}

// ContainerIDContains checks if a container ID contains a specified prefix.
// It splits the container ID by '//' and checks if the second part of the split string starts with the prefix.
// It returns true if the prefix is found, and false otherwise.
func ContainerIDContains(containerID string, prefix string) bool {
	parts := strings.Split(containerID, "//")
	if len(parts) == 2 && strings.HasPrefix(parts[1], prefix) {
		return true
	}

	return false
}
