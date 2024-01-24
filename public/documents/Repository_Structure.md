# Repository Structure Guide

Welcome to the Repository Structure Guide for the Tarian Detector project. This document will help you understand the structure and organization of our project repository.

## 📖 Table of Contents

1. [Repository Structure](#repository-structure)
2. [Root Directory](#root-directory)
3. [Cmd Directory](#cmd-directory)
4. [Documents Directory](#documents-directory)
5. [Headers Directory](#headers-directory)
6. [Pkg Directory](#headers-directory)

## Repository Structure

```
├── bin
│   └── tarian_detector
├── CHANGELOG.md
├── cmd
│   └── tarian_detector
│       ├── k8s.go
│       └── main.go
├── Code_of_Conduct.md
├── Credits_Acknowledgement.md
├── go.mod
├── go.sum
├── headers
│   ├── bpf_core_read.h
│   ├── bpf_endian.h
│   ├── bpf_helper_defs.h
│   ├── bpf_helpers.h
│   ├── bpf_tracing.h
│   └── vmlinux.h
├── LICENSE
├── Maintainers.md
├── Makefile
├── pkg
│   ├── detector
│   │   └── detector.go
│   ├── eBPF
│   │   ├── handler.go
│   │   ├── hook.go
│   │   ├── map.go
│   │   ├── module.go
│   │   └── program.go
│   ├── err
│   │   └── err.go
│   ├── eventparser
│   │   ├── context.go
│   │   ├── parser.go
│   │   └── probes.go
│   ├── k8s
│   │   ├── container.go
│   │   └── k8s.go
│   └── utils
│       ├── converter.go
│       ├── network.go
│       └── utils.go
├── public
│   ├── callgraphs
│   │   ├── c
│   │   │   ├── file_close.png
│   │   │   ├── file_openat2.png
│   │   │   ├── file_openat.png
│   │   │   ├── file_open.png
│   │   │   ├── file_read.png
│   │   │   ├── file_readv.png
│   │   │   ├── file_write.png
│   │   │   ├── file_writev.png
│   │   │   ├── process_execveat.png
│   │   │   └── process_execve.png
│   │   └── go
│   │       ├── main.svg
│   │       └── README.md
│   ├── documents
│   │   ├── Contributor_Guidelines.md
│   │   ├── Development_Guide.md
│   │   ├── File_Contribution _Guide.md
│   │   ├── images
│   │   │   └── testing
│   │   │       ├── 5.12.0-aws.png
│   │   │       ├── 5.16.11-aws.png
│   │   │       ├── 5.19.0-local.png
│   │   │       ├── 5.8.0-aws.png
│   │   │       └── 5.9.0-aws.png
│   │   ├── Installation_Guide.md
│   │   ├── Repository_Structure.md
│   │   ├── Testing.md
│   │   └── Use_Case.md
│   └── images
│       ├── architecture-diagram.png
│       └── tarian-logo.png
├── README.md
├── RELEASENOTES.md
└── tarian
    ├── c
    │   ├── common.h
    │   ├── tarian.bpf.c
    │   └── utils
    │       ├── buffer.h
    │       ├── context.h
    │       ├── index.h
    │       ├── meta.h
    │       ├── shared
    │       │   ├── codes.h
    │       │   ├── constants.h
    │       │   ├── index.h
    │       │   ├── maps.h
    │       │   ├── nsproxy.h
    │       │   ├── task.h
    │       │   ├── types.h
    │       │   └── writer.h
    │       ├── shared.h
    │       └── tarian.h
    ├── tarian_bpfel_x86.go
    ├── tarian_bpfel_x86.o
    └── tarian.go
```

## Root Directory

- `CHANGELOG.md`: This file contains a curated, chronologically ordered list of notable changes for each version of the Tarian Detector project.
- `Code_of_Conduct.md`: This document outlines our expectations for participants within our community, as well as steps for reporting unacceptable behavior.
- `Credits_Acknowledgement.md`: This file acknowledges and gives credits to all contributors of the Tarian Detector project.
- `LICENSE`: This file contains the license terms for the Tarian Detector project.
- `Maintainers.md`: This file lists the maintainers of the Tarian Detector project.
- `Makefile`: This is a special file that helps to compile and manage the Tarian Detector project, containing sets of instructions for the make command.
- `README.md`: This file provides an overview of the project, its usage, installation instructions, and other important information.
- `RELEASENOTES.md`: This document provides notes for each release including new features, improvements, and fixes.
- `tarian-logo.png`: The logo of the Tarian Detector project.

## Cmd Directory
The `cmd` directory contains the executable binaries or the main applications for the project.
- `tarian_detector`: This directory contains the source code for the command-line interface of the Tarian Detector project.
  - `main.go`: The main entry point for the CLI application.

## Documents Directory
The `documents` directory contains the following files:

- `Contributor_Guidelines.md`: This document provides guidelines for anyone who wishes to contribute to the project.

- `Development_Guide.md`: This document provides instructions and guidelines for developing on this project.

- `File_Contribution_Guide.md`: This document provides guidelines on how to contribute files to the project.

- `Installation_Guide.md`: This document provides detailed instructions on how to install and set up the project.

- `Repository_Structure.md`: This document provides an overview of the structure of the repository and describes what each directory and file is used for.

## Headers Directory
This directory contains header files used in the Tarian Detector project.
- `bpf_core_read.h`, `bpf_endian.h`, `bpf_helper_defs.h`, `bpf_helpers.h`, `bpf_tracing.h`, `vmlinux.h`: These are various header files used in the project.

## Pkg Directory
The `pkg` directory is where the reusable and exportable packages for the Tarian Detector project reside.
- `detector`: This directory contains the source code for the detector functionality of the project.
- `ebpf`: This directory contains the source code related to eBPF (Extended Berkeley Packet Filter) operations, including code for file and network operations, as well as process entry and exit handling. Please note: each subdirectory in the `ebpf` directory contains `.go` files for the respective operations, `.bpf.c` files for the corresponding eBPF programs, and `.o` files as a result of compiling the eBPF programs.

Feel free to explore the repository and familiarize yourself with the structure and content of the various files and directories. Happy coding!
