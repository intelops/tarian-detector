// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package main

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/intelops/tarian-detector/pkg/detector"
	"github.com/intelops/tarian-detector/pkg/k8s"
	"k8s.io/client-go/rest"
)

func main() {
	// Start kubernetes watcher
	watcher, err := K8Watcher()
	if err != nil {
		if !errors.Is(err, rest.ErrNotInCluster) {
			log.Fatal(err)
		}

		log.Print("Kubernetes environment not detected. The Kubernetes context has been disabled.")
	} else {
		watcher.Start()
	}

	// Loads the ebpf programs
	bpfLinker, err := LoadPrograms(BpfModules)
	if err != nil {
		log.Fatal(err)
	}

	// Converts bpf handlers to detectors
	eventDetectors, err := GetDetectors(bpfLinker.ProbeHandlers)
	if err != nil {
		log.Fatal(err)
	}

	// Instantiate event detectors
	eventsDetector := detector.NewEventsDetector()

	// Add ebpf programs to detectors
	eventsDetector.Add(eventDetectors)

	// Start and defer Close
	err = eventsDetector.Start()
	if err != nil {
		log.Fatal(err)
	}
	defer eventsDetector.Close()

	log.Printf("%d detectors running...\n\n", eventsDetector.Count())

	// Loop read events
	go func() {
		for {
			e, err := eventsDetector.ReadAsInterface()
			if err != nil {
				fmt.Println(err)
			}

			if watcher != nil {
				containerId, err := k8s.ProcsContainerID(e["process_id"].(uint32))
				if err != nil {
					continue
				}

				if len(containerId) != 0 {
					pod := watcher.FindPod(containerId)

					k8sInfo := struct {
						Podname        string
						PodUid         string
						Namespace      string
						ContainerID    string
						PodLabels      map[string]string
						PodAnnotations map[string]string
					}{}

					if pod != nil {
						k8sInfo = struct {
							Podname        string
							PodUid         string
							Namespace      string
							ContainerID    string
							PodLabels      map[string]string
							PodAnnotations map[string]string
						}{
							Podname:        pod.GetName(),
							Namespace:      pod.GetNamespace(),
							ContainerID:    containerId,
							PodLabels:      pod.GetLabels(),
							PodAnnotations: pod.GetAnnotations(),
							PodUid:         string(pod.GetUID()),
						}

					}

					k8sInfo.ContainerID = containerId
					e["kubernetes"] = k8sInfo
				}
			}

			printEvent(e)
			// stats(eventsDetector)
		}
	}()

	// Only for avoiding deadlock detection
	for {
		time.Sleep(1 * time.Minute)
	}
}

func printEvent(data map[string]any) {
	div := "======================"
	msg := ""
	for ky, val := range data {
		msg += fmt.Sprintf("%s: %v\n", ky, val)
	}

	log.Printf("%s\n%s%s\n", div, msg, div)
}

func stats(d *detector.EventsDetector) {
	fmt.Print("\033[H\033[2J")
	fmt.Printf("%d detectors running...\n", d.Count())
	fmt.Printf("Total Record captured %d\n", d.TotalRecordsCount)

	fmt.Printf("Event wise count...\n\n")
	for k, v := range d.ProbeRecordsCount {
		fmt.Printf("%s: %d\n", k, v)
	}
}
