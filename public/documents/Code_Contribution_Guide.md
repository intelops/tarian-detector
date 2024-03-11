# Tarian Detector Project: Code Contribution Guide

Welcome to the Code Contribution Guide for the Tarian Detector project. This guide will help you understand how to effectively organize and contribute code to our project.

## Table of Contents

- [Introduction](#introduction)
- [Adding Files](#adding-files)
- [The Detector Directory](#the-detector-directory)
  - [EventDetector Interface](#eventdetector-interface)
  - [EventsDetector Struct](#eventsdetector-struct)
- [Adding eBPF Programs](#adding-ebpf-programs)
- [eBPF Programs and Adding New System Call Hooks](#ebpf-programs-and-adding-new-system-call-hooks)
  - [Naming Kernel Space eBPF Programs](#naming-kernel-space-ebpf-programs)
- [Example Kernel Program](#example-kernel-program)
- [Code Contribution Workflow](#code-contribution-workflow)
- [Documenting Your Changes](#documenting-your-changes)

## Introduction

Effective file management is crucial for the success of an open-source project. A well-structured repository makes it easier for all contributors to navigate the project and contribute their own work. This guide will walk you through the steps for correctly adding new code to our project.

## Adding Files

When adding files, it's important to place them in the appropriate directory within the project hierarchy. Here's a brief overview of our repository's structure and the types of files each directory should contain:

- `Root Directory`: Contains high-level files like README.md, CHANGELOG.md, LICENSE, etc.
- `Cmd Directory`: Contains the main applications code for the project.
- `Public Directory`: Contains all necessary project documentations and public files.
- `Headers Directory`: Contains ebpf header files used in the project.
- `Pkg Directory`: Contains the reusable and exportable packages for the project.

When creating a new file, it’s important to ensure that it includes the necessary copyright and license details at the top of the file. To assist with this, the project provides the following command:

```bash
make file FILE_PATH=/your/file/path/filename.ext
```

## The Detector Directory

The [detector](/pkg/detector) directory, located inside the [pkg](/pkg/) directory, contains the source code for the detector functionality of the project. If your contribution is related to the detection functionalities, you should add your code files in this directory.

The [detector.go](/pkg/detector/detector.go) file located in the `detector` package plays a vital role in the Tarian Detector project. This file contains the core abstractions and functionality for handling different types of detectors.

### EventDetector Interface

The `EventDetector` interface is a contract for all the types of event detectors within the project. Any new event detector that you add to the project should conform to this interface, which includes three methods:

1. `Count()`: This method returns the number of detectors running.
2. `Close()`: This method halts the event detection process.
3. `ReadAsInterface()`: This method retrieves the detected events.

### EventsDetector Struct

The `EventsDetector` struct is a manager for the various event detectors in the project. It includes:

- `detectors`: This slice holds all the individual event detectors.
- `eventQueue`: This is a buffered channel that acts as a queue for all the detected events from different detectors.
- `started` and `closed`: These boolean flags indicate whether the `EventsDetector` has been started or closed.
- `totalRecordsCount`, `probeRecordsCount` and `totalDetectors`  are utilized for tracking the total records, probe specific records count, and current running detectors count respectively.

The struct has several associated methods for managing the lifecycle and operation of the event detectors:

1. `NewEventsDetector()`: This function constructs a new `EventsDetector` instance.
2. `Add(detector EventDetector)`: This method allows you to add a new detector to the `detectors` slice.
3. `Start()`: This method starts all the detectors and listens to the events from them.
4. `Close()`: This method closes all the detectors and stops listening to their events.
5. `ReadAsInterface()`: This method fetches the next event from the event queue.
6. `GetTotalCount()`: This method returns the total number of records received.
7. `GetProbeCount()`: This method returns the total number of probe specific records received.
8. `Count()`: This method returns the total number of detectors running.

Each new type of detector added to the project should be integrated into an `EventsDetector` instance using the `Add()` method. The `EventsDetector` takes care of the lifecycle and event collection of all the integrated detectors.

This is the broad structural overview of the `detector.go` file. As a contributor, it is crucial to understand this structure as it will guide you in adding new event detectors or modifying existing ones.

## Adding eBPF Programs

eBPF (Extended Berkeley Packet Filter) programs provide the functionality for file and network operations, as well as process entry and exit handling. If you want to add a new eBPF hook, you should place it in the [tarian.bpf.c](/tarian/c/tarian.bpf.c) file within the [tarian/c](/tarian/c/) directory.

Extended Berkeley Packet Filter (eBPF) provides robust capabilities for process introspection, including monitoring system calls, network activity, and more. eBPF operates by running compact programs within a restricted virtual machine in the kernel, ensuring system safety. These programs gather data about the system state for subsequent analysis or alteration.

In the given example, an eBPF program is utilized to monitor the network accept system call, `__x64_sys_accept`. This system call is commonly used by server applications to accept incoming network connections.

## eBPF Programs and Adding New System Call Hooks

The interaction between eBPF programs and corresponding Go programs facilitates a range of functionality. Let's consider a template case of a network accept system call's associated eBPF program - [tdf_accept_e](/tarian/c/tarian.bpf.c#L516)

### eBPF Program Template - [accept syscall](/tarian/c/tarian.bpf.c#L516)

The eBPF program, `tdf_accept_e`, attaches a `kprobe` to the `__x64_sys_accept` system call. `kprobes` provide a mechanism for setting dynamic breakpoints in any kernel routine, which is useful for gathering debug and performance data. Here, the `kprobe` captures information about the function arguments and emits it as a `perf` event which is then stored in a `perf` event array map and is accessible to user-space applications.

### Adding a New System Call Hook

When adding a new system call hook, you can follow the structure of the aforementioned template. Here's a generalized workflow:

1. **Identify the Target System Call:**

    - Determine the specific system call you want to monitor. You’ll use its name to create a new eBPF program.
    - For instance, if you’re interested in monitoring the listen system call, your program name would be `tdf_listen_e`.
2. **Write an eBPF Program:**

    - Within the [tarian.bpf.c](/tarian/c/tarian.bpf.c) file, create the eBPF program corresponding to the chosen system call.
    - Your program should attach to any of the tarian-detector supported hooks like kprobe, kretprobe, raw tracepoint, etc. and collect relevant data (such as function arguments).
3. **Update Userspace Files:**
    - In the [tarian.go](/tarian/tarian.go) userspace file, add the corresponding probe for your system call.
    - Additionally, provide relevant information about the system call in the `GenerateTarianEvents` function within the  [probes.go](pkg/eventparser/probes.go) file. Once added, the probe will be automatically monitored by the userspace component.
4. **Customize Event Processing (Optional):**
    - If you require specialized handling of the received event field beyond the default behavior, you can extend the functionality by updating the `TarianEventMap` field named `function`.

## Naming Kernel Space eBPF Programs

When creating an eBPF program that runs in the kernel space, follow this naming convention:

1. Begin with the name of the system call you intend to monitor.
2. Append `tdf_` (which stands for “Tarian Detector Function”) to the system call name.
3. Finally, add either `_e` (for entry point) or `_r` (for return point).

For example:

If you’re monitoring the entry point of the `accept` system call, name your eBPF kernel space program as `tdf_accept_e`.

This consistent naming convention helps organize and identify your eBPF programs effectively.

## Example Kernel Program

```C
KPROBE("__x64_sys_accept")
int BPF_KPROBE(tdf_accept_e, struct pt_regs *regs) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_ACCEPT_E, &te, VARIABLE,  TDS_ACCEPT_E);
  if (resp != TDC_SUCCESS) {
    stats__add(resp);
    return resp;
  }

  /*====================== PARAMETERS ======================*/

  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}
```

**Here’s a brief explanation of the code:**

- `KPROBE("__x64_sys_accept")`: This line attaches the eBPF program to the accept system call in the kernel. The accept system call is used to accept a new connection on a socket.
- `int BPF_KPROBE(tdf_accept_e, struct pt_regs *regs)`: This is the definition of the eBPF program. The program is named `tdf_accept_e` following the naming convention for the Tarian Detector project. The `struct pt_regs *regs` argument is a pointer to the CPU registers at the time the `accept` system call was invoked.
- `tarian_event_t te;`: This line declares a variable `te` of type `tarian_event_t`. This type is presumably a structure that represents an event in the Tarian Detector system.
- `int resp = new_event(ctx, TDE_SYSCALL_ACCEPT_E, &te, VARIABLE,  TDS_ACCEPT_E);`: This line calls the `new_event` function to initialize a new event. The event type is `TDE_SYSCALL_ACCEPT_E`, which is defined in [constants.h](/tarian/c/utils/shared/constants.h#105) an accept system call event.
- `if (resp != TDC_SUCCESS) { stats__add(resp); return resp; }`: This checks if the `new_event` function was successful. If not, it increments some statistics and returns the error code.
- `return tdf_submit_event(&te);`: This line submits the event to the Tarian Detector system for processing.

By following these naming conventions, we ensure that our codebase remains consistent and easy to understand. This also facilitates easier navigation and debugging for all contributors. Thank you for adhering to these conventions while contributing to the Tarian Detector project.

## Code Contribution Workflow

When contributing to the Tarian Detector project, you need to understand how the project's workflow operates. Here are the steps to contribute your eBPF programs:

1. **Kernel Space Program:** Write your eBPF program that runs in the kernel space. This should be related to a specific syscall that you wish to monitor. Remember to follow the [Naming Kernel Space eBPF Programs](#naming-kernel-space-ebpf-programs) provided.
2. **User Space Program:**  In the [tarian](/tarian) folder in the file [tarian.go](/tarian/tarian.go). This is where you integrate your ebpf program. Here are the steps to add them:

   a. **Add Program to Module:** Follow the existing pattern in the file. For example, if you have created a network accept program, you would add it like this:

   ```go
   tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfAcceptE, ebpf.NewHookInfo().Kprobe("__x64_sys_accept")))
   tarianDetectorModule.AddProgram(ebpf.NewProgram(bpfObjs.TdfAcceptR, ebpf.NewHookInfo().Kretprobe("__x64_sys_accept")))
   ```

   b. **Register Event:** Register your newly add event to the events map. This can be done like this in [probes.go](/pkg/eventparser/probes.go):

    ```go
    accept_e := NewTarianEvent(43, "sys_accept_entry", 880,
      Param{name: "fd", paramType: TDT_S32, linuxType: "int"},
      Param{name: "upeer_sockaddr", paramType: TDT_SOCKADDR, linuxType: "struct sockaddr *"},
      Param{name: "upper_addrlen", paramType: TDT_S32, linuxType: "int *"},
    )
    events.AddTarianEvent(TDE_SYSCALL_ACCEPT_E, accept_e)
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

Your contributions to the Tarian Detector project are greatly appreciated! By adhering to this guide, you aid in maintaining the organization of our repository and the smooth operation of our project.
