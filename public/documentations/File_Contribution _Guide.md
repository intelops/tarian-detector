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

-----

The `tarian_bpfel_x86.go` file in the Tarian Detector project plays a crucial role in interfacing with the eBPF (Extended Berkeley Packet Filter) components, specifically compiled for the x86 architecture. Here's a breakdown of its functionality and structure:

### Key Components of `tarian_bpfel_x86.go`

1. **Package Declaration**: The file is part of the `bpf` package, aligning it with other eBPF-related files in the project.

2. **Imports**: It imports standard Go libraries and essential eBPF-related packages, such as `github.com/cilium/ebpf`, which is a common library for working with eBPF in Go.

3. **Data Structures**:
   - `tarianEventDataT`: Defines a complex struct that likely represents the data structure of events captured by the eBPF programs. It includes fields like timestamps, task information, event IDs, syscall numbers, processor IDs, buffer data, and system information.

4. **eBPF Collection Loading Functions**:
   - `loadTarian()`: Loads the eBPF program specifications from an embedded object file (`tarian_bpfel_x86.o`) into an `ebpf.CollectionSpec`.
   - `loadTarianObjects()`: Utilizes the loaded `CollectionSpec` to load and assign eBPF objects into the kernel. This function is versatile and can work with various object types, such as maps and programs.

5. **Specs and Objects**:
   - The file contains multiple structs that define the specifications (`tarianSpecs`, `tarianProgramSpecs`, `tarianMapSpecs`) and the actual loaded objects (`tarianObjects`, `tarianMaps`, `tarianPrograms`) for eBPF programs and maps. These are crucial for managing the lifecycle of eBPF components within the kernel.

6. **Program and Map Definitions**:
   - Detailed definitions for various eBPF programs (`Kprobe`, `Kretprobe`) and maps (`Events`) are provided, allowing the kernel to understand what functions and data structures are being loaded and how to interact with them.

7. **Closing Functions**:
   - Functions like `Close()` in `tarianObjects`, `tarianMaps`, and `tarianPrograms` are defined for proper cleanup and deallocation of resources within the kernel when the eBPF programs and maps are no longer needed.

8. **Embedded eBPF Bytecode**:
   - The file contains an embedded eBPF object file (`tarian_bpfel_x86.o`), which is the compiled eBPF bytecode. This is loaded into the kernel to perform various monitoring and data capturing tasks.
-----

The `tarian.go` file in the Tarian Detector project is an essential part of the eBPF implementation, specifically focusing on loading and configuring eBPF programs and maps for the system's monitoring and detection capabilities. Let's break down its key functionalities:

### Key Functionalities of `tarian.go`

1. **Package Declaration**: The file is part of the `bpf` package, which is consistent with the other eBPF-related files in the project.

2. **BPF Generation Command**: The file includes a `go:generate` directive to run `bpf2go`, a tool used to generate Go bindings for eBPF programs. It specifies the use of `clang` and other flags for compiling the eBPF C code (`tarian.bpf.c`) and generating corresponding Go code.

3. **Function `GetDetectors`**:
   - This function initializes a `BpfModule` named `detectors`.
   - It calls `getBpfObject()` to load eBPF objects (programs and maps) into the kernel.
   - The function then assigns various eBPF programs to the `detectors` module. These programs are associated with different system calls (e.g., `execve`, `open`, `read`, `write`, `socket`, `accept`, etc.) and are set up as kprobes and kretprobes.
   - Each eBPF program in the module has an ID, hook type, name, and a flag indicating whether it should be attached.

4. **Function `getBpfObject`**:
   - This function loads the eBPF objects into a `tarianObjects` struct using `loadTarianObjects`.
   - It handles the loading of eBPF specs, like maps and programs, from the compiled eBPF bytecode.

5. **Structs and Types**:
   - The file defines `tarianObjects`, which is used to hold the loaded eBPF programs and maps.
   - `loadTarianObjects` and `getBpfObject` functions work together to load these objects based on the specifications generated by `bpf2go`.

### Contribution Opportunities in `tarian.go`

Contributors interested in enhancing the eBPF aspect of the Tarian Detector project can focus on several areas in this file:

1. **Adding New eBPF Programs**: Introduce new eBPF programs for additional monitoring or detection capabilities.

2. **Optimizing Existing Programs**: Improve the efficiency or accuracy of the current eBPF programs.

3. **Enhancing Program Configuration**: Make the program configuration more flexible or dynamic, allowing for runtime adjustments.

4. **Improving Error Handling**: Ensure robust error handling and reporting for the eBPF loading and attaching processes.

5. **Performance Tuning**: Optimize the performance of eBPF program loading and execution, which is crucial for systems-level monitoring.

6. **Testing and Documentation**: Adding comprehensive tests and detailed documentation for the eBPF loading process and the functionalities of each eBPF program.

Contributing to `tarian.go` requires a solid understanding of Go, eBPF, and system-level programming. Given the critical role of eBPF in monitoring and detection in the Tarian Detector project, any changes or enhancements should be thoroughly tested and reviewed to maintain the integrity and performance of the system.

-----
The `tarian.go` file in the `eventparser` package of the Tarian Detector project is focused on parsing and interpreting system call arguments. It plays a crucial role in analyzing and formatting the data captured by the eBPF programs for further processing or monitoring. Here's an overview of its key functionalities:

### Key Functionalities of `parser.go` in the `eventparser` Package

1. **Package Declaration**: The file is part of the `eventparser` package, indicating its role in parsing and interpreting event data.

2. **SysArg Struct**:
   - Represents a system call argument.
   - Contains fields like `Name`, `Description`, `Type`, and `Function`. The `Function` is a custom parser function to convert the argument value into a readable format.

3. **Syscall Struct**:
   - Represents a system call.
   - Contains fields like `Id`, `Name`, and a slice of `SysArg` representing the arguments of the syscall.

4. **Arg Struct**:
   - A simple struct to hold the name and value of a parsed argument.

5. **Syscalls Map**:
   - A map of system call IDs to `Syscall` structs.
   - It predefines a set of system calls (like `sys_read`, `sys_write`, `sys_open`, etc.) and their associated arguments.

6. **Function `ParseArg`**:
   - A method of the `SysArg` struct.
   - It parses an argument value based on the custom parser function defined in `SysArg`.
   - If no custom parser is defined, it converts the value to a string using `fmt.Sprintf`.

7. **Custom Argument Parsing**:
   - The design allows for custom parsing logic for different argument types, making the system flexible and capable of handling a variety of data formats.

### How to Contribute to `tarian.go` in the `eventparser` Package

Contributors interested in enhancing the system call parsing and interpretation aspect of the Tarian Detector project can focus on several areas in this file:

1. **Adding New System Calls**: Introduce parsing logic for additional system calls that might be relevant for monitoring or detection.

2. **Enhancing Argument Parsing**: Improve the parsing mechanisms for existing arguments, especially for complex data types.

3. **Optimizing Performance**: Ensure that the argument parsing is efficient, especially for high-frequency system calls.

4. **Extending Custom Parsing Functions**: Develop more sophisticated custom parsing functions for specific argument types.

5. **Improving Documentation**: Add detailed comments and documentation, particularly for custom parsing functions, to make it easier for other developers to understand and contribute.

6. **Testing**: Create comprehensive tests for different system calls and their arguments to ensure accurate parsing and error handling.

Contributing to this part of the project requires a good understanding of system calls, their arguments, and how they can be interpreted meaningfully. It's also important to ensure that any changes are compatible with the eBPF programs capturing these system calls.

---

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