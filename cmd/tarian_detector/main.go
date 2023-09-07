// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package main

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/intelops/tarian-detector/pkg/detector"
	"github.com/intelops/tarian-detector/pkg/linker"
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
	defer stats(eventsDetector, bpfLinker)

	// Loop read events
	go func() {
		for {
			e, err := eventsDetector.ReadAsInterface()
			if err != nil {
				fmt.Println(err)
			}

			k8sCtx, err := GetK8sContext(watcher, e["process_id"].(uint32))
			if err != nil {
				log.Print(err)
				e["kubernetes"] = err.Error()
			} else {
				e["kubernetes"] = k8sCtx
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

func stats(d *detector.EventsDetector, l *linker.Linker) {
	// fmt.Print("\033[H\033[2J")
	fmt.Printf("\n\n%d detectors running...\n", d.Count())
	fmt.Printf("Total Record captured %d\n", d.TotalRecordsCount)

	fmt.Printf("Event wise count...\n\n")
	countTriggered := 0
	for k, v := range l.ProbeIds {
		if !v {
			// skips the disabled probes
			continue
		}

		_, keyExists := d.ProbeRecordsCount[k]
		if keyExists {
			countTriggered++
			fmt.Printf("%s: %d\n", k, d.ProbeRecordsCount[k])
		} else {
			fmt.Printf("%s: 0\n", k)
		}
	}

	fmt.Printf("\n%d events triggered in total.\n", countTriggered)
}
