package main

import (
	"fmt"
	"log"
	"time"

	"github.com/intelops/tarian-detector/pkg/detector"
	"github.com/intelops/tarian-detector/pkg/ebpf/c/process_entry"
	"github.com/intelops/tarian-detector/pkg/ebpf/c/process_exit"
)

func main() {
	// Instantiate event detectors
	processEntryDetector := process_entry.NewProcessEntryDetector()
	processExitDetector := process_exit.NewProcessExitDetector()

	// Register them to the events detector (composite)
	eventsDetector := detector.NewEventsDetector()
	eventsDetector.Add(processEntryDetector)
	eventsDetector.Add(processExitDetector)

	// Start and defer Close
	err := eventsDetector.Start()
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

			switch event := e.(type) {
			case process_entry.EntryEventData:
				printProcessEntryEventData(event)
			case process_exit.ExitEventData:
				printProcessExitEventData(event)
			}
		}
	}()

	// Only for avoiding deadlock detection
	for {
		time.Sleep(1 * time.Minute)
	}
}

func printProcessEntryEventData(event process_entry.EntryEventData) {
	fmt.Println("# process_entry.EntryEventData:")
	fmt.Printf("Pid: %d\n", event.Pid)
	fmt.Printf("BinaryFilePath: %s\n", event.BinaryFilepath[:])
	fmt.Printf("Comm: %s\n", event.Comm[:])
	fmt.Println("")
}

func printProcessExitEventData(event process_exit.ExitEventData) {
	fmt.Println("# process_exit.ExitEventData:")
	fmt.Printf("Pid: %d\n", event.Pid)
	fmt.Printf("Comm: %s\n", event.Comm[:])
	fmt.Println("")
}
