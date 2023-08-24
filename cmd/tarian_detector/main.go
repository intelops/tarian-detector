// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package main

import (
	"fmt"
	"log"
	"time"

	"github.com/intelops/tarian-detector/pkg/detector"
)

func main() {
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

			printEvent(e)
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
