# File Contribution Guide

Welcome to the File Contribution Guide for the Tarian Detector project. This guide will help you understand how to effectively organize and contribute files to our project.

## Table of Contents

- [Introduction](#introduction)
- [Adding Files](#adding-files)
- [The Detector Directory](#the-detector-directory)
    - [EventDetector Interface](#eventdetector-interface)
    - [EventsDetector Struct](#eventsdetector-struct)
- [Updating the Main Code](#updating-the-main-code)
    - [The Main.go File](#the-main-go-file)
        - [Instantiating Event Detectors](#instantiating-event-detectors)
        - [Managing Event Detectors](#managing-event-detectors)
- [Adding eBPF Programs](#adding-ebpf-programs)
- [eBPF Programs and How to Add New System Call Hooks](#ebpf-programs-and-how-to-add-new-system-call-hooks)
    - [Kernel Space Program Naming](#kernel-space-program-naming)
    - [User Space Program Naming](#user-space-program-naming)
    - [Function Naming in Kernel Space Program](#function-naming-in-kernel-space-program)
- [Examples](#examples)
- [Code Contribution Workflow](#code-contribution-workflow)
- [Documenting Your Changes](#documenting-your-changes)
## Introduction

Effective file management is crucial for the success of an open-source project. A well-structured repository makes it easier for all contributors to navigate the project and contribute their own work. This guide will walk you through the steps for correctly adding new files to our project.

## Adding Files

You should place your files in the correct directory of the project hierarchy. Below is a brief overview of our repository's structure and the types of files you might add to each directory:

- `Root Directory`: Contains high-level files like README.md, CHANGELOG.md, LICENSE, etc.
- `Cmd Directory`: Contains the executable binaries or main applications for the project.
- `Documents Directory`: Contains all necessary project documentation.
- `Headers Directory`: Contains header files used in the project.
- `Pkg Directory`: Contains the reusable and exportable packages for the project.

## The Detector Directory

The [detector](/pkg/detector) directory, located inside the [pkg](/pkg/) directory, contains the source code for the detector functionality of the project. If your contribution is related to the detection functionalities, you should add your code files in this directory.

The [detector.go](/pkg/detector/detector.go) file located in the `detector` package plays a vital role in the Tarian Detector project. This file contains the core abstractions and functionality for handling different types of detectors.

### EventDetector Interface

The `EventDetector` interface is a contract for all the types of event detectors within the project. Any new event detector that you add to the project should conform to this interface, which includes three methods:

1. `Start()`: This method initiates the event detection process.
2. `Close()`: This method halts the event detection process.
3. `ReadAsInterface()`: This method retrieves the detected events.

### EventsDetector Struct

The `EventsDetector` struct is a manager for the various event detectors in the project. It includes:

- `detectors`: This slice holds all the individual event detectors.
- `eventQueue`: This is a buffered channel that acts as a queue for all the detected events from different detectors.
- `started` and `closed`: These boolean flags indicate whether the `EventsDetector` has been started or closed.

The struct has several associated methods for managing the lifecycle and operation of the event detectors:

1. `NewEventsDetector()`: This function constructs a new `EventsDetector` instance.
2. `Add(detector EventDetector)`: This method allows you to add a new detector to the `detectors` slice.
3. `Start()`: This method starts all the detectors and listens to the events from them.
4. `Close()`: This method closes all the detectors and stops listening to their events.
5. `ReadAsInterface()`: This method fetches the next event from the event queue.

Each new type of detector added to the project should be integrated into an `EventsDetector` instance using the `Add()` method. The `EventsDetector` takes care of the lifecycle and event collection of all the integrated detectors.

This is the broad structural overview of the `detector.go` file. As a contributor, it is crucial to understand this structure as it will guide you in adding new event detectors or modifying existing ones.

## Updating the Main Code

If you are making changes to the main code, you should modify the [main.go](/cmd/dev-cli/main.go) file located in the [cmd](/cmd/) directory. Ensure you thoroughly test your changes and follow the coding conventions used throughout the project.

## The Main.go File

The `main.go` file in the `cmd` directory serves as the entry point of the Tarian Detector application. Here is a brief overview of its structure and operation:

### Instantiating Event Detectors

The `main()` function begins by creating instances of each type of event detector available in the application, including process, file, and network event detectors.

### Managing Event Detectors

Next, an `EventsDetector` instance is created. This object acts as a manager for all the individual event detectors. Each of the instantiated event detectors is then added to this `EventsDetector` using its `Add()` method.

### Starting Event Detection

The `Start()` method of `EventsDetector` is called to initiate the event detection process for all the detectors. The `Close()` method is deferred to ensure that all detectors will be properly stopped when the program ends.

### Reading and Handling Events

A separate Goroutine is started to continuously read events from the `EventsDetector`. For each event, the code determines its type and calls the appropriate function to handle and print the event data.

### Keeping the Application Running

Finally, an infinite loop is used to prevent the application from prematurely exiting, as it's designed to be a long-running application.

As a contributor, understanding the workflow and structure of the `main.go` file is essential. It coordinates the operations of the entire application and is a key area you might update when adding new detectors or modifying existing ones.


## Adding eBPF Programs

eBPF (Extended Berkeley Packet Filter) programs provide the functionality for file and network operations, as well as process entry and exit handling. If you need to add a new eBPF program, you should place it in the [ebpf](/pkg/ebpf/) subdirectory within the `pkg` directory. Each subdirectory in the `ebpf` directory should contain `.go` files for the respective operations, `.bpf.c` files for the corresponding eBPF programs, and `.o` files as a result of compiling the eBPF programs.

Extended Berkeley Packet Filter (eBPF) provides robust capabilities for process introspection,including monitoring system calls, network activity, and more. eBPF operates by running compact programs within a restricted virtual machine in the kernel, ensuring system safety. These programs gather data about the system state for subsequent analysis or alteration.

In the given example, an eBPF program is utilized to monitor the network accept system call, `__x64_sys_accept`. This system call is commonly used by server applications to accept incoming network connections.


## eBPF Programs and How to Add New System Call Hooks

The interaction between eBPF programs and corresponding Go programs facilitates a range of functionality. Let's consider a template case of a network accept system call and its associated eBPF and Go programs - [accept.bpf.c](/pkg/ebpf/c/network_accept/accept.bpf.c) and [network_accept.go](/pkg/ebpf/c/network_accept/network_accept.go) respectively.

### eBPF Program Template - [accept.bpf.c](/pkg/ebpf/c/network_accept/accept.bpf.c)

The eBPF program, `accept.bpf.c`, attaches a `kprobe` to the `__x64_sys_accept` system call. `kprobes` provide a mechanism for setting dynamic breakpoints in any kernel routine, which is useful for gathering debug and performance data. Here, the `kprobe` captures information about the function arguments and emits it as a `perf` event which is then stored in a `perf` event array map and is accessible to user-space applications.

### Go Program Template - [network_accept.go](/pkg/ebpf/c/network_accept/network_accept.go)

The associated Go program, `network_accept.go`, uses the `cilium/ebpf` library to interact with the eBPF program. The `Start` method loads the compiled eBPF program, attaches the `kprobe` to the `__x64_sys_accept` system call, and begins monitoring the event. The `Read` method retrieves an event from the eBPF program, transforms it into a Go-friendly format, and returns it for further processing.

### Adding a New System Call Hook

When adding a new system call hook, you can follow the structure of the aforementioned template. Here's a generalized workflow:

1. Identify the system call you wish to monitor. Use its name to create a new `.bpf.c` file within the `ebpf` directory (e.g., `your_system_call.bpf.c`).
2. In this new `.bpf.c` file, write an eBPF program that attaches a `kprobe` to the identified system call, collects the necessary data (e.g., function arguments), and emits it as a `perf` event.
3. Create a corresponding Go program in the same directory (e.g., `domain-name_your_system_call.go`). This program should load the compiled eBPF program, attach the `kprobe`, and implement methods to start the monitoring, read the events, and stop the monitoring.
4. Make sure to handle the conversion of eBPF events into a Go-compatible format that can be easily processed by your application.

Remember, eBPF and Go programs should be created under a specific subdirectory within the `ebpf` directory. This subdirectory should ideally be named according to the operation it monitors (e.g., `your_domain_your_hook`), containing the respective `.go` files for operations, `.bpf.c` files for the eBPF programs, and `.o` files resulting from the compilation of the eBPF programs.

## Naming  Programs

## Kernel Space Program Naming

The name of the eBPF program that runs in the kernel space should be the syscall used, followed by `.bpf.c`. For example, if the syscall is `accept`, the eBPF kernel space program should be named `accept.bpf.c`.

## User Space Program Naming

The name of the eBPF program that runs in the user space should follow the pattern `domain-name_syscall-name.go`. The domain name refers to whether the program is for process, file, or network operations.

## Function Naming in Kernel Space Program

Inside the eBPF kernel space program, the function name should follow the pattern `"hook-used"_"syscall-used"`. The hook used could be `kprobe`, `kretprobe`, etc. The syscall used is the syscall that the program intends to hook.

## Examples


```C
SEC("kprobe/__x64_sys_accept")
int kprobe_accept(struct pt_regs *ctx)
{
    .
    .
    .

    return 0;
}
```

For example if you are writing an ebpf program for this accept syscall using kprobe you need to  adhere to the following naming conventions:

1. Kernel Space Program: For an eBPF program that hooks the `accept` syscall, the kernel space program should be named `accept.bpf.c`.
   
2. User Space Program: For an eBPF program that deals with network operations and hooks the `accept` syscall, the user space program should be named `network_accept.go`.

3. Function Naming in Kernel Space Program: For an eBPF program that uses a `kprobe` hook and hooks the `__x64_sys_accept` syscall, the function should be named `kprobe___x64_sys_accept`.

By following these naming conventions, we ensure that our codebase remains consistent and easy to understand. This also facilitates easier navigation and debugging for all contributors. Thank you for adhering to these conventions while contributing to the Tarian Detector project.

## Code Contribution Workflow

When contributing to the Tarian Detector project, you need to understand how the project's workflow operates. Here are the steps to contribute your eBPF programs:

1. **Kernel Space Program:** Write your eBPF program that runs in the kernel space. This should be related to a specific syscall that you wish to monitor. Remember to follow the [naming convention](#naming-ebpf-programs) provided.

2. **User Space Program:** Write the corresponding userspace program for the syscall used in the Kernel Space Program. This program should follow the domain name and syscall pattern as detailed in the naming convention.

3. **Update Main Program:** The main program resides in the [cmd](/cmd) folder under the name [dev-cli](/cmd/dev-cli/). This is where you integrate your detectors. Here are the steps to update the main program:

   a. **Instantiate Event Detectors:** Create a new instance of your event detector. Follow the existing pattern in the main program. For example, if you have created a network accept detector, you would instantiate it like this:
   ```C
    networkAcceptDetector:=network_acceptNewNetworkAcceptDetector().
    ```

   b. **Register Event Detectors:** Register your newly instantiated event detector to the events detector. This can be done like this: 
   
   ```C
   `eventsDetector.Add(networkAcceptDetector)`.
    ```

   c. **Loop Read Events:** Add your event data type to the event loop. Follow the existing switch-case pattern. For example: 
   
   ```go
   case *network_accept.AcceptEventData:
   printNetworkAcceptEventData(event)
   ```

## Documenting Your Changes

Whenever you add new files or make significant modifications, you should document these changes. This will help other contributors understand the purpose of your contribution and the changes you made. This can usually be done within a pull request.

## Examples

Here we provide a couple of example scenarios to demonstrate how to add files to our project:

1. Adding a new feature:
    - Create a new branch for your feature.
    - Add your code files in the correct directory according to the functionality they provide.
    - Document your changes in the pull request.

2. Adding a new document:
    - Create a new branch for your documentation.
    - Add your `.md` file in the `documents` directory.
    - Document your changes in the pull request.

Thank you for your contributions to the Tarian Detector project! By following this guide, you help keep our repository organized and our project running smoothly.
