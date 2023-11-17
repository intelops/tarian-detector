# File Contribution Guide

Welcome to the File Contribution Guide for the Tarian Detector project. This guide is designed to assist contributors in understanding how to effectively organize and contribute files to our project. We'll focus particularly on the `pkg` directory, which is a key part of our codebase.

## 📖 Table of Contents

1. [Overview of Major Directories](#overview-of-major-directories)
2. [Deep Dive into `pkg` Directory](#deep-dive-into-pkg-directory)
   1. [Detector](#detector)
   2. [eBPF](#ebpf)
   3. [Eventparser](#eventparser)
   4. [K8s](#k8s)
   5. [Utils](#utils)

## Overview of Major Directories

Our repository is organized into several major directories:

1. **Root**: Contains global files like README, LICENSE, and general documentation.
2. **Cmd**: Houses the main application's executable code.
3. **Headers**: Contains header files for eBPF operations.
4. **Pkg**: A crucial directory with core logic and functionalities.
5. **Public**: Includes public resources such as images and documentation.

## Deep Dive into `pkg` Directory

Exploring the `pkg` directory in-depth will provide a clear understanding of each file's purpose and functionality in your Tarian Detector project. Let's break down the contents of each subdirectory and file within `pkg`:

### 1. Detector Subdirectory
- **`detector.go`**: This is the main file in the `detector` subdirectory. It likely contains the core logic for the detection mechanisms employed by the Tarian Detector. Functions in this file may include initializing detection processes, defining detection rules or algorithms, and handling detected events or anomalies.

### 2. eBPF Subdirectory
- **`bpf.go`**: This file is responsible for initializing and managing eBPF (Extended Berkeley Packet Filter) programs. It might include code to load eBPF programs into the kernel, handle eBPF maps, and interact with eBPF subsystems.
- **`c` Directory**: Contains C language files specifically for eBPF operations.
  - **`common.h`**: A header file that likely contains common definitions and structures used by other eBPF C files.
  - **`tarian.bpf.c`**: The main eBPF program written in C, which probably contains the logic for packet filtering, monitoring, or data collection at the kernel level.
  - **`utils_c` Directory**: Contains utility headers for eBPF operations in C.
    - **`buffer.h`, `context.h`, `index.h`**: These header files likely contain utility functions and structures for buffer management, execution context, and indexing.
    - **`shared` Directory**: Stores shared resources and common definitions.
      - **`constants.h`, `error_codes.h`, `maps.h`, `nsproxy.h`, `task.h`, `types.h`**: These headers define various constants, error codes, map structures, and data types used throughout the eBPF program.
    - **`shared.h`**: A consolidated header file that might include common functions or definitions used across multiple eBPF C files.
    - **`sys_args.h`**: Header file for system call arguments, likely used in eBPF programs to interact with system calls.
- **`tarian_bpfel_x86.go` & `tarian_bpfel_x86.o`**: These are the Go and compiled object files for the eBPF program, tailored for x86 architecture.
- **`tarian.go`**: This Go file might include higher-level functions or wrappers around the eBPF functionalities.

The `bpf.go` file in your Tarian Detector project is a crucial component for handling eBPF (Extended Berkeley Packet Filter) operations. Let's break down its functionality and explore how someone can contribute to it.

### Overview of `bpf.go`
1. **Imports**: The file imports necessary packages from `github.com/cilium/ebpf`, `link`, and `ringbuf`, which are essential for working with eBPF in Go.

2. **Interfaces and Types**:
   - `Module` Interface: Defines a method for creating a new eBPF module.
   - `HookType`: An enumeration representing different types of hooks (e.g., Tracepoint, Kprobe, etc.).
   - `Hook`: A struct that describes a hook with its type, group, name, and options.
   - `BpfProgram`: Represents an eBPF program with an ID, associated hook, and other properties.
   - `BpfModule`: Contains the ID, a slice of `BpfPrograms`, and an eBPF map.
   - `Handler`: Manages the eBPF programs, including map readers and probe links.

3. **Core Functions**:
   - `NewBpfModule()`: Initializes a new `BpfModule` with empty `BpfPrograms`.
   - `AttachProbe()`: Method to attach a probe based on the type of hook (e.g., Tracepoint, Kprobe).
   - `Start()`: Starts the eBPF module, attaching necessary probes and creating a map reader.
   - `ReadAsInterface()`: Reads data from the eBPF map as a byte slice.
   - `Close()`: Closes all probe links and the map reader.

4. **Helper Functions**:
   - `createMapReader()`: Creates a new ring buffer reader for the eBPF map.

### Contribution Opportunities

1. **Adding New Hook Types**:
   - The file currently handles several hook types. Contributors can add support for new eBPF hook types if required by the project.

2. **Enhancing Error Handling**:
   - Contributors can improve error messages and handling throughout the file, making the module more robust and user-friendly.

3. **Optimizing Performance**:
   - Performance enhancements, such as optimizing the way eBPF programs are attached or the map is read, are always valuable.

4. **Adding Tests and Examples**:
   - Writing tests for different functionalities in `bpf.go` would greatly improve reliability. Also, providing examples of how to use the defined structs and functions would be beneficial.

5. **Documentation and Comments**:
   - Adding more in-depth comments and documentation within the code can make it easier for new contributors to understand the file's functionality.

6. **Extending Functionality**:
   - Contributors can extend the functionalities of `BpfModule`, `BpfProgram`, or `Handler` to cater to more advanced eBPF use cases.

7. **Code Refactoring**:
   - Simplifying or refactoring complex parts of the code for better readability and maintenance is always helpful.

The `bpf.go` file is a core component of the Tarian Detector project, dealing with intricate eBPF operations. Contributions to this file should be made with a clear understanding of eBPF and its application within the project.

### 3. Eventparser Subdirectory
- **`context.go`, `parser.go`, `probes.go`**: These files are likely involved in parsing and interpreting events captured by the system. They might include logic for event context management, actual parsing of event data, and definitions of various probes or triggers used in event detection.

### 4. K8s Subdirectory
- **`container.go`**: This file possibly contains functionalities related to Kubernetes container management, such as container status monitoring or interaction with container runtime.
- **`k8s.go`**: A broader file for Kubernetes-related operations, which might include integrations with Kubernetes APIs, handling Kubernetes resources, or Kubernetes cluster management functions.

### 5. Utils Subdirectory
- **`converter.go`**: Likely includes utility functions for data type conversions or transformations.
- **`network.go`**: This file probably contains network-related utility functions, such as network status checks, network configuration utilities, or network communication functions.
- **`utils.go`**: A general utility file that might house a variety of helper functions used across the project.

Each of these files plays a vital role in the functionality of the Tarian Detector project. Understanding their purpose and interaction helps contributors make meaningful and coherent contributions to the project.

## Contributing to `pkg`

Contributors are encouraged to familiarize themselves with the structure and purpose of each file within the `pkg` directory. When contributing:

1. Ensure your changes align with the purpose of the file.
2. Follow coding standards and guidelines as outlined in our `Contributor_Guidelines.md`.
3. Test your changes thoroughly before submitting a pull request.
4. Include documentation updates if you add new features or change existing functionalities.

Thank you for your interest in contributing to the Tarian Detector project. Your contributions help us build a stronger and more effective tool for our community.

---