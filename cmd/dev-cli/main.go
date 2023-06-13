package main

import (
	"fmt"
	"log"

	"github.com/intelops/tarian-detector/pkg/ebpf/c/process_entry"
)

func main() {
	processEntryDetector := process_entry.NewProcessEntryDetector()
	err := processEntryDetector.Start()
	if err != nil {
		log.Fatal(err)
	}

	defer processEntryDetector.Close()

	fmt.Println("Detecting process entry")
	for {
		event, err := processEntryDetector.Read()
		if err != nil {
			fmt.Println(err)
		}

		fmt.Println(string(event.BinaryFilepath[:]))
		fmt.Println(string(event.Comm[:]))
	}
}
