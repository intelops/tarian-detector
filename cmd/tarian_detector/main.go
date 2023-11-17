// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package main

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/intelops/tarian-detector/pkg/detector"
	bpf "github.com/intelops/tarian-detector/pkg/eBPF"
	"k8s.io/client-go/rest"
)

func main() {
	// Start kubernetes watcher
	watcher, err := K8Watcher()
	if err != nil {
		if !errors.Is(err, rest.ErrNotInCluster) {
			log.Fatal(err)
		}

		log.Print(NotInClusterErrMsg)
	} else {
		watcher.Start()
	}

	BpfModules, err := bpf.GetDetectors()
	if err != nil {
		log.Fatal(err)
	}

	detectors, err := BpfModules.Start()
	if err != nil {
		log.Fatal(err)
	}

	// Instantiate event detectors
	eventsDetector := detector.NewEventsDetector()

	// Add ebpf programs to detectors
	eventsDetector.Add(detectors)

	// Start and defer Close
	err = eventsDetector.Start()
	if err != nil {
		log.Fatal(err)
	}
	defer eventsDetector.Close()

	log.Printf("%d detectors running...\n\n", eventsDetector.Count())
	// defer stats(eventsDetector, bpfLinker)

	count := 0
	// Loop read events
	go func() {
		for {
			e, err := eventsDetector.ReadAsInterface()
			if err != nil {
				fmt.Println(err)
			}

			k8sCtx, err := GetK8sContext(watcher, e["host_pid"].(uint32))
			if err != nil {
				// log.Print(err)
				e["kubernetes"] = err.Error()
			} else {
				e["kubernetes"] = k8sCtx
			}

			// printEvent(e)
			count++
			fmt.Println("Total count:", count)
			// if count > 1000 {
			// 	os.Exit(1)
			// }
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
