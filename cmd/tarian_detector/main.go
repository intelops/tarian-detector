// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/intelops/tarian-detector/pkg/detector"
	"github.com/intelops/tarian-detector/tarian"
)

// main is the entry point of the application. It sets up the necessary components
// and starts the main event loop.
func main() {
	// Create a channel to listen for interrupt signals (Ctrl+C or SIGTERM)
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	start_time := time.Now()

	// Initialize and start the Kubernetes watcher
	// watcher, err := K8Watcher()
	// if err != nil {
	// 	log.Print(err)
	// } else {
	// 	watcher.Start()
	// }

	// Initialize Tarian eBPF module
	tarianEbpfModule, err := tarian.GetModule()
	if err != nil {
		log.Fatal(err)
	}

	// Prepare the Tarian detector by attaching eBPF programs and creating map readers
	tarianDetector, err := tarianEbpfModule.Prepare()
	if err != nil {
		log.Fatal(err)
	}

	// Instantiate the event detectors
	eventsDetector := detector.NewEventsDetector()

	// Add the eBPF module to the detectors
	eventsDetector.Add(tarianDetector)

	// Start the event detectors and defer their closure
	err = eventsDetector.Start()
	if err != nil {
		log.Fatal(err)
	}
	defer eventsDetector.Close()

	log.Printf("%d probes running...\n\n", eventsDetector.Count())

	count := 0
	go func() {
		<-stopper // Wait for an interrupt signal

		eventsDetector.Close()
		log.Printf("Total records captured : %d\n", eventsDetector.GetTotalCount())
		count := 1
		for ky, vl := range eventsDetector.GetProbeCount() {
			fmt.Printf("%d. %s: %d\n", count, ky, vl)
			count++
		}
		os.Exit(0)
	}()

	/************* stats start *************/
	go func() {
		tarian.Statistics(&count, start_time)
	}()
	/************* stats end *************/

	/********************* neglible data loss start ************************/

	// resultChan := make(chan detector.Result, 8192)
	// eventsDetector.ReadAsInterface(resultChan)
	// for {
	// 	res := <-resultChan
	// 	if res.Err != nil {
	// 		log.Print(err)
	// 		continue
	// 	}

	// 	count++
	// 	// utils.PrintEvent(res.Data, eventsDetector.GetTotalCount())
	// }

	/********************* neglible data loss end ************************/

	/********************* data loss ************************/

	for {
		_, err := eventsDetector.ReadAsInterface()
		if err != nil {
			fmt.Println(err)
		}

		count++
	}

	/********************* data loss ************************/
}
