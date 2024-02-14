// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/intelops/tarian-detector/pkg/detector"
	"github.com/intelops/tarian-detector/tarian"
	"k8s.io/client-go/rest"
)

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

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

	tarianEbpfModule, err := tarian.GetModule()
	if err != nil {
		log.Fatal(err)
	}

	tarianDetector, err := tarianEbpfModule.Prepare()
	if err != nil {
		log.Fatal(err)
	}

	// Instantiate event detectors
	eventsDetector := detector.NewEventsDetector()

	// Add ebpf programs to detectors
	eventsDetector.Add(tarianDetector)

	// Start and defer Close
	err = eventsDetector.Start()
	if err != nil {
		log.Fatal(err)
	}
	defer eventsDetector.Close()

	log.Printf("%d probes running...\n\n", eventsDetector.Count())

	go func() {
		<-stopper

		eventsDetector.Close()
		os.Exit(0)
	}()

	// Loop read events
	go func() {
		for {
			e, err := eventsDetector.ReadAsInterface()
			if err != nil {
				fmt.Println(err)
			}

			k8sCtx, err := GetK8sContext(watcher, e["hostProcessId"].(uint32))
			if err != nil {
				e["kubernetes"] = err.Error()
			} else {
				e["kubernetes"] = k8sCtx
			}

			// printEvent(e, eventsDetector.GetTotalCount())
		}
	}()

	// Only for avoiding deadlock detection
	for {
		time.Sleep(1 * time.Minute)
	}
}

func printEvent(data map[string]any, t int) {
	div := "=================================="
	msg := ""
	for ky, val := range data {
		msg += fmt.Sprintf("%s: %v\n", ky, val)
	}

	log.Printf("Total captured %d.\n%s\n%s%s\n", t, div, msg, div)
}
