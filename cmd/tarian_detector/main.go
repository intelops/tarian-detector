// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package main

import (
	"fmt"
	"log"
	"time"

	"github.com/intelops/tarian-detector/pkg/inspector/detector"
)

func main() {
	// Instantiate event detectors
	eventsDetector := detector.NewEventsDetector()

	// Loads the ebpf programs
	bpfPrograms, err := getEbpfPrograms()
	if err != nil {
		log.Fatal(err)
	}

	// Add ebpf programs to detectors
	eventsDetector.Add(bpfPrograms)

	// Start and defer Close
	err = eventsDetector.Start()
	if err != nil {
		log.Fatal(err)
	}
	defer eventsDetector.Close()

	fmt.Print("Running detectors...\n\n")

	// Loop read events
	go func() {
		for {
			e, err := eventsDetector.ReadAsInterface()
			if err != nil {
				fmt.Println(err)
			}

			printEvent(e)
		}
	}()

	// Only for avoiding deadlock detection
	for {
		time.Sleep(1 * time.Minute)
	}
}

func printEvent(data map[string]any) {
	fmt.Println("======================")
	for ky, val := range data {
		fmt.Printf("%s: %v\n", ky, val)
	}
	fmt.Println("======================")
}
