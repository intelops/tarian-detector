package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/intelops/tarian-detector/pkg/detector"
	"github.com/intelops/tarian-detector/pkg/ebpf/c/file_close"
	"github.com/intelops/tarian-detector/pkg/ebpf/c/file_open"
	"github.com/intelops/tarian-detector/pkg/ebpf/c/file_openat"
	"github.com/intelops/tarian-detector/pkg/ebpf/c/file_openat2"
	"github.com/intelops/tarian-detector/pkg/ebpf/c/file_read"
	"github.com/intelops/tarian-detector/pkg/ebpf/c/file_readv"
	"github.com/intelops/tarian-detector/pkg/ebpf/c/file_write"
	"github.com/intelops/tarian-detector/pkg/ebpf/c/file_writev"
	"github.com/intelops/tarian-detector/pkg/ebpf/c/process_entry"
	"github.com/intelops/tarian-detector/pkg/ebpf/c/process_exit"
	"github.com/intelops/tarian-detector/pkg/ebpf/c/network_socket"
	"github.com/intelops/tarian-detector/pkg/ebpf/c/network_connect"
	"github.com/intelops/tarian-detector/pkg/ebpf/c/network_listen"
	"github.com/intelops/tarian-detector/pkg/ebpf/c/network_bind"
	"github.com/intelops/tarian-detector/pkg/ebpf/c/network_accept"
)

func main() {
	// Instantiate event detectors

	processEntryDetector := process_entry.NewProcessEntryDetector()
	processExitDetector := process_exit.NewProcessExitDetector()
	fileOpenat2Detector := file_openat2.NewOpenat2Detector()
	fileOpenatDetector := file_openat.NewOpenatDetector()
	fileOpenDetector := file_open.NewOpenDetector()
	fileCloseDetector := file_close.NewCloseDetector()
	fileReadDetector := file_read.NewReadDetector()
	fileReadvDetector := file_readv.NewReadvDetector()
	fileWriteDetector := file_write.NewWriteDetector()
	fileWritevDetector := file_writev.NewWritevDetector()
	networkSocketDetector := network_socket.NewNetworkSocketDetector()
	networkConnectDetector := network_connect.NewNetworkConnectDetector()
	networkListenDetector := network_listen.NewNetworkListenDetector()
	networkBindDetector := network_bind.NewNetworkBindDetector()
	networkAcceptDetector := network_accept.NewNetworkAcceptDetector()
	// Register them to the events detector (composite)
	eventsDetector := detector.NewEventsDetector()
	
	eventsDetector.Add(processEntryDetector)
	eventsDetector.Add(processExitDetector)

	//File Open
	eventsDetector.Add(fileOpenDetector)
	eventsDetector.Add(fileOpenatDetector)
	eventsDetector.Add(fileOpenat2Detector)

	//File Close
	eventsDetector.Add(fileCloseDetector)

	//File Read
	eventsDetector.Add(fileReadDetector)
	eventsDetector.Add(fileReadvDetector)

	//File Write
	eventsDetector.Add(fileWriteDetector)
	eventsDetector.Add(fileWritevDetector)

	//Network 
	eventsDetector.Add(networkSocketDetector)
	eventsDetector.Add(networkConnectDetector)
	eventsDetector.Add(networkListenDetector)
	eventsDetector.Add(networkBindDetector)
	eventsDetector.Add(networkAcceptDetector)
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
			case *network_socket.SocketEventData:
				printProcessSocketEventData(event)
			case *network_connect.ConnectEventData:
				printNetworkConnectEventData(event)
			case *network_listen.ListenEventData:
				printNetworkListenEventData(event)
			case *network_bind.BindEventData:
				printNetworkBindEventData(event)
			case *network_accept.AcceptEventData:
				printNetworkAcceptEventData(event)
			default:
				printEvent(event)
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


func printProcessSocketEventData(event *network_socket.SocketEventData) {
	fmt.Println("#  network_socket.SocketEventData:")
	fmt.Printf("Pid: %d\n", event.Pid)
	fmt.Printf("Tgid: %d\n", event.Tgid)
	fmt.Printf("Uid: %d\n", event.Uid)
	fmt.Printf("Gid: %d\n", event.Gid)
	fmt.Printf("Domain: %s\n", network_socket.Domain(event.Domain))
	fmt.Printf("Type : %s\n", network_socket.Type(event.Type))
	fmt.Printf("Protocol: %s\n", network_socket.Protocol(event.Protocol))
	j, _ := json.Marshal(event)
	fmt.Println(string(j))
	fmt.Println("")
}

func printNetworkConnectEventData(event *network_connect.ConnectEventData) {
	addressFamily, ipAddr , portStr := event.InterpretFamilyAndIP()
	fmt.Println("#  network_connect.ConnectEventData:")
	fmt.Printf("Pid: %d\n", event.Pid)
	fmt.Printf("Tgid: %d\n", event.Tgid)
	fmt.Printf("Uid: %d\n", event.Uid)
	fmt.Printf("Gid: %d\n", event.Gid)
	fmt.Printf("Fd: %d\n", event.Fd)
	fmt.Printf("Address Family: %s\n",addressFamily)
	fmt.Printf("IPAddress: %s\n", ipAddr)
	fmt.Printf("Port: %d\n", portStr)
	fmt.Printf("Address Length: %d\n", event.Addrlen)
	j, _ := json.Marshal(event)
	fmt.Println(string(j))
	fmt.Println("")
}

func printNetworkListenEventData(event *network_listen.ListenEventData) {
	fmt.Println("#  network_Listen.ListenEventData:")
	fmt.Printf("Fd: %d\n", event.Fd)
	fmt.Printf("Queue: %d\n", event.Backlog)
	j, _ := json.Marshal(event)
	fmt.Println(string(j))
	fmt.Println("")
}

func printNetworkBindEventData(event *network_bind.BindEventData) {
	addressFamily, ipAddr , portStr := event.InterpretFamilyAndIP()
	fmt.Println("#  network_bind.BindEventData:")
	fmt.Printf("Pid: %d\n", event.Pid)
	fmt.Printf("Tgid: %d\n", event.Tgid)
	fmt.Printf("Uid: %d\n", event.Uid)
	fmt.Printf("Gid: %d\n", event.Gid)
	fmt.Printf("Fd: %d\n", event.Fd)
	fmt.Printf("AddressFamily: %s\n",addressFamily)
	fmt.Printf("IPAddress: %s\n", ipAddr)
	fmt.Printf("Port: %d\n", portStr)
	fmt.Printf("Address length: %d\n", event.Addrlen)
	j, _ := json.Marshal(event)
	fmt.Println(string(j))
	fmt.Println("")
}

func printNetworkAcceptEventData(event *network_accept.AcceptEventData) {
	addressFamily, ipAddr , portStr := event.InterpretFamilyAndIP()
	fmt.Println("#  network_accept.AcceptEventData:")
	fmt.Printf("Pid: %d\n", event.Pid)
	fmt.Printf("Tgid: %d\n", event.Tgid)
	fmt.Printf("Uid: %d\n", event.Uid)
	fmt.Printf("Gid: %d\n", event.Gid)
	fmt.Printf("Fd: %d\n", event.Fd)
	fmt.Printf("AddressFamily: %s\n",addressFamily)
	fmt.Printf("IPAddress: %s\n", ipAddr)
	fmt.Printf("Port: %d\n", portStr)
	j, _ := json.Marshal(event)
	fmt.Println(string(j))
	fmt.Println("")
}



func printEvent(data any) {
	fmt.Printf("# %T:\n %v\n\n", data, data)
}
