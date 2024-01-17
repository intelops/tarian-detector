// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/intelops/tarian-detector/pkg/detector"
	"github.com/intelops/tarian-detector/pkg/utils"
	"github.com/intelops/tarian-detector/tarian"
)

func main() {
	// Start kubernetes watcher
	// watcher, err := K8Watcher()
	// if err != nil {
	// 	if !errors.Is(err, rest.ErrNotInCluster) {
	// 		log.Fatal(err)
	// 	}

	// 	log.Print(NotInClusterErrMsg)
	// } else {
	// 	watcher.Start()
	// }

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

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

	log.Printf("%d detectors running...\n\n", eventsDetector.Count())
	// defer stats(eventsDetector, bpfLinker)

	count := 0
	var mutex sync.Mutex
	go func() {

		select {
		case <-stopper:
			// case <-time.After(10 * time.Second):
			eventsDetector.Close()
			fmt.Println("records captured count in 10s: ", count)
			os.Exit(0)
		}
	}()

	// Loop read events
	go func() {
		for {
			e, err := eventsDetector.ReadAsInterface()
			if err != nil {
				fmt.Println(err)
			}

			// k8sCtx, err := GetK8sContext(watcher, e["host_pid"].(uint32))
			// if err != nil {
			// 	// log.Print(err)
			// 	e["kubernetes"] = err.Error()
			// } else {
			// 	e["kubernetes"] = k8sCtx
			// }

			// if e["cwd"] != "/home/cravela@appstekcorp.local/Projects/DOUBLE/DELETE/DELETE/tarian-detector/" {
			// 	continue
			// }

			if err := utils.WriteJSONToFile(e, "exec_id.json", &mutex); err != nil {
				fmt.Println("Error writing:", err)
			}

			count++
			printEvent(0, count, e)
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

func printEvent(rc int, t int, data map[string]any) {
	div := "======================"
	msg := ""
	for ky, val := range data {
		msg += fmt.Sprintf("%s: %v\n", ky, val)
	}

	log.Printf("%s\nStatus of ring buffer %d. Remaining %d, Total: %d\n%s%s\n", div, data["processor_id"], rc/14865, t, msg, div)
}
