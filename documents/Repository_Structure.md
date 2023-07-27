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
├── CHANGELOG.md
├── cmd
│   └── dev-cli
│       └── main.go
├── Code_of_Conduct.md
├── Credits_Acknowledgement.md
├── documents
│   ├── Contributor_Guidelines.md
│   ├── Development_Guide.md
│   └── Installation_Guide.md
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
│   └── ebpf
│       └── c
│           ├── file_close
│           │   ├── close.bpf.c
│           │   ├── close_bpfel_x86.go
│           │   ├── close_bpfel_x86.o
│           │   └── file_close.go
│           ├── file_open
│           │   ├── file_open.go
│           │   ├── open.bpf.c
│           │   ├── open_bpfel_x86.go
│           │   └── open_bpfel_x86.o
│           ├── file_openat
│           │   ├── file_openat.go
│           │   ├── openat.bpf.c
│           │   ├── openat_bpfel_x86.go
│           │   └── openat_bpfel_x86.o
│           ├── file_openat2
│           │   ├── file_openat2.go
│           │   ├── openat2.bpf.c
│           │   ├── openat2_bpfel_x86.go
│           │   └── openat2_bpfel_x86.o
│           ├── file_read
│           │   ├── file_read.go
│           │   ├── read.bpf.c
│           │   ├── read_bpfel_x86.go
│           │   └── read_bpfel_x86.o
│           ├── file_readv
│           │   ├── file_readv.go
│           │   ├── readv.bpf.c
│           │   ├── readv_bpfel_x86.go
│           │   └── readv_bpfel_x86.o
│           ├── file_write
│           │   ├── file_write.go
│           │   ├── write.bpf.c
│           │   ├── write_bpfel_x86.go
│           │   └── write_bpfel_x86.o
│           ├── file_writev
│           │   ├── file_writev.go
│           │   ├── writev.bpf.c
│           │   ├── writev_bpfel_x86.go
│           │   └── writev_bpfel_x86.o
│           ├── network_accept
│           │   ├── accept.bpf.c
│           │   ├── accept_bpfel_x86.go
│           │   ├── accept_bpfel_x86.o
│           │   └── network_accept.go
│           ├── network_bind
│           │   ├── bind.bpf.c
│           │   ├── bind_bpfel_x86.go
│           │   ├── bind_bpfel_x86.o
│           │   └── network_bind.go
│           ├── network_connect
│           │   ├── connect.bpf.c
│           │   ├── connect_bpfel_x86.go
│           │   ├── connect_bpfel_x86.o
│           │   └── network_connect.go
│           ├── network_listen
│           │   ├── listen.bpf.c
│           │   ├── listen_bpfel_x86.go
│           │   ├── listen_bpfel_x86.o
│           │   └── network_listen.go
│           ├── network_socket
│           │   ├── network_socket.go
│           │   ├── socket.bpf.c
│           │   ├── socket_bpfel_x86.go
│           │   └── socket_bpfel_x86.o
│           ├── process_entry
│           │   ├── entry.bpf.c
│           │   ├── entry_bpfel_x86.go
│           │   ├── entry_bpfel_x86.o
│           │   └── process_entry.go
│           └── process_exit
│               ├── exit.bpf.c
│               ├── exit_bpfeb.go
│               ├── exit_bpfeb.o
│               ├── exit_bpfel.go
│               ├── exit_bpfel.o
│               └── process_exit.go
├── README.md
├── RELEASENOTES.md
└── tarian-logo.png
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
- `dev-cli`: This directory contains the source code for the command-line interface of the Tarian Detector project.
  - `main.go`: The main entry point for the CLI application.

## Documents Directory
This directory contains all the necessary documentation for the project.
- `Contributor_Guidelines.md`: This guide helps contributors understand how they can contribute to the Tarian Detector project.
- `Development_Guide.md`: This document provides instructions on how to set up a development environment for the Tarian Detector project.
- `Installation_Guide.md`: This guide provides detailed instructions on how to install and set up the Tarian Detector project.

## Headers Directory
This directory contains header files used in the Tarian Detector project.
- `bpf_core_read.h`, `bpf_endian.h`, `bpf_helper_defs.h`, `bpf_helpers.h`, `bpf_tracing.h`, `vmlinux.h`: These are various header files used in the project.

## Pkg Directory
The `pkg` directory is where the reusable and exportable packages for the Tarian Detector project reside.
- `detector`: This directory contains the source code for the detector functionality of the project.
- `ebpf`: This directory contains the source code related to eBPF (Extended Berkeley Packet Filter) operations, including code for file and network operations, as well as process entry and exit handling. Please note: each subdirectory in the `ebpf` directory contains `.go` files for the respective operations, `.bpf.c` files for the corresponding eBPF programs, and `.o` files as a result of compiling the eBPF programs.

Feel free to explore the repository and familiarize yourself with the structure and content of the various files and directories. Happy coding!
