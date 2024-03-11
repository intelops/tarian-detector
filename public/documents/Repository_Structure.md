# Repository Structure Guide

Welcome to the Repository Structure Guide for the Tarian Detector project. This document will help you understand the structure and organization of our project repository.

## 📖 Table of Contents

1. [Repository Structure](#repository-structure)
2. [Root Directory](#root-directory)
3. [Cmd Directory](#cmd-directory)
4. [Headers Directory](#headers-directory)
5. [Pkg Directory](#headers-directory)
6. [Public Directory](#public-directory)
    - [Callgraphs Directory](#callgraphs-directory)
    - [Documents Directory](#documents-directory)
    - [Images Directory](#images-directory)
7. [Tarian Directory](#tarian-directory)

## Repository Structure

```bash
.
├── bin
│   └── tarian_detector
├── CHANGELOG.md
├── cmd
│   └── tarian_detector
│       ├── k8s.go
│       └── main.go
├── Code_of_Conduct.md
├── Credits_Acknowledgement.md
├── go.mod
├── go.sum
├── headers
│   ├── bpf_core_read.h
│   ├── bpf_endian.h
│   ├── bpf_helper_defs.h
│   ├── bpf_helpers.h
│   ├── bpf_tracing.h
│   └── vmlinux.h
├── LICENSE
├── Maintainers.md
├── Makefile
├── pkg
│   ├── detector
│   │   ├── detector.go
│   │   └── detector_test.go
│   ├── eBPF
│   │   ├── handler.go
│   │   ├── handler_test.go
│   │   ├── hook.go
│   │   ├── hook_test.go
│   │   ├── map.go
│   │   ├── map_test.go
│   │   ├── module.go
│   │   ├── module_test.go
│   │   ├── program.go
│   │   └── program_test.go
│   ├── err
│   │   ├── err.go
│   │   └── err_test.go
│   ├── eventparser
│   │   ├── context.go
│   │   ├── parser.go
│   │   ├── parser_test.go
│   │   ├── probes.go
│   │   ├── probes_test.go
│   │   ├── transform.go
│   │   └── transform_test.go
│   ├── k8s
│   │   ├── container.go
│   │   └── k8s.go
│   └── utils
│       ├── converter.go
│       ├── converter_test.go
│       ├── utils.go
│       └── utils_test.go
├── public
│   ├── callgraphs
│   │   ├── c
│   │   │   ├── README.md
│   │   │   └── tarian.bpf.png
│   │   └── go
│   │       ├── main.svg
│   │       └── README.md
│   ├── documents
│   │   ├── Contributor_Guidelines.md
│   │   ├── Development_Guide.md
│   │   ├── File_Contribution _Guide.md
│   │   ├── images
│   │   │   └── testing
│   │   │       ├── 5.12.0-aws.png
│   │   │       ├── 5.16.11-aws.png
│   │   │       ├── 5.19.0-local.png
│   │   │       ├── 5.8.0-aws.png
│   │   │       └── 5.9.0-aws.png
│   │   ├── Installation_Guide.md
│   │   ├── Repository_Structure.md
│   │   ├── Testing_Guide.md
│   │   ├── Testing.md
│   │   └── Use_Case.md
│   └── images
│       ├── architecture-diagram.png
│       └── tarian-logo.png
├── README.md
├── RELEASENOTES.md
├── SECURITY.md
└── tarian
    ├── c
    │   ├── common.h
    │   ├── tarian.bpf.c
    │   └── utils
    │       ├── filters.h
    │       ├── index.h
    │       ├── meta.h
    │       ├── shared
    │       │   ├── codes.h
    │       │   ├── constants.h
    │       │   ├── index.h
    │       │   ├── maps.h
    │       │   ├── nsproxy.h
    │       │   ├── task.h
    │       │   ├── types.h
    │       │   └── writer.h
    │       ├── shared.h
    │       ├── stats.h
    │       └── tarian.h
    ├── tarian.go
    ├── tarian_test.go
    ├── tarian_x86_bpfel.go
    └── tarian_x86_bpfel.o

23 directories, 86 files
```

## [Root Directory](.)

- `CHANGELOG.md`: This file contains a curated, chronologically ordered list of notable changes for each version of the Tarian Detector project.
- `Code_of_Conduct.md`: This document outlines our expectations for participants within our community, as well as steps for reporting unacceptable behavior.
- `Credits_Acknowledgement.md`: This file acknowledges and gives credits to all contributors of the Tarian Detector project.
- `LICENSE`: This file contains the license terms for the Tarian Detector project.
- `Maintainers.md`: This file lists the maintainers of the Tarian Detector project.
- `Makefile`: This is a special file that helps to compile and manage the Tarian Detector project, containing sets of instructions for the make command.
- `README.md`: This file provides an overview of the project, its usage, installation instructions, and other important information.
- `RELEASENOTES.md`: This document provides notes for each release including new features, improvements, and fixes.

## [Cmd Directory](/cmd)

The `cmd` directory contains the executable binaries or the main applications for the project.

- `tarian_detector`: This directory contains the source code for the command-line interface of the Tarian Detector project.
  - `main.go`: The main entry point for the CLI application.

## [Headers Directory](/headers)

This directory contains header files used in the Tarian Detector project.

- `bpf_core_read.h`, `bpf_endian.h`, `bpf_helper_defs.h`, `bpf_helpers.h`, `bpf_tracing.h`, `vmlinux.h`: These are various header files used in the project.

## [Pkg Directory](/pkg)

The `pkg` directory is where the reusable and exportable packages for the Tarian Detector project reside.

- `detector`: This directory contains the source code for the detector functionality of the project.
- `ebpf`: This directory contains the source code for the eBPF (Extended Berkeley Packet Filter) functionality of the project.
- `err`: This directory contains the source code for the error handling functionality of the project.
- `eventparser`: This directory contains the source code for the event parser functionality of the project.
- `k8s`: This directory contains the source code for the Kubernetes context enrichment of the project.
- `utils`: This directory contains the source code for the utility functions of the project.

## Public Directory

The `public` directory contains the following subdirectories:

### [Callgraphs Directory](/public/callgraphs/)

This directory houses the project’s source code call graphs.

### [Documents Directory](/public/documents/)

The `documents` directory contains the following files:

- `Code_Contribution_Guide.md`: This document provides guidelines on how to contribute your part of code to the project.
- `Contributor_Guidelines.md`: This document provides guidelines for anyone who wishes to contribute to the project.
- `Development_Guide.md`: This document provides instructions and guidelines for developing on this project.
- `Installation_Guide.md`: This document provides detailed instructions on how to install and set up the project.
- `Repository_Structure.md`: This document provides an overview of the structure of the repository and describes what each directory and file is used for.
- `Testing_Guide.md`: This document provides instructions and guidelines for testing the project.
- `Testing.md`: This document details how we tested the project and outlines future testing plans.
- `Use_Case.md`: This document provides an overview of the use cases of the project.

### [Images Directory](/public/images/)

This directory contains images that are referenced within the project.

## [Tarian Directory](/tarian)

The `tarian` directory contains the source code related to eBPF (Extended Berkeley Packet Filter) operations, including code for file and network operations, as well as process entry and exit handling.

Feel free to explore the repository and familiarize yourself with the structure and content of the various files and directories. Happy coding!
