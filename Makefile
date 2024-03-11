# SPDX-License-Identifier: Apache-2.0
# Copyright 2024 Authors of Tarian & the Organization created Tarian

# executable Files Path
EXECUTABLE=bin

# executable File name
EXECUTABLE_FILE = tarian_detector

# header files path in the project.
HEADERS_PATH=headers

# required C header files
HEADERS_FILES = bpf_helpers bpf_helper_defs bpf_endian bpf_core_read bpf_tracing

# extracts the major, minor, and patch version numbers of the kernel version
KERNEL_VERSION = $(word 1, $(subst -, ,$(shell uname -r)))
KV_S = $(subst ., ,$(KERNEL_VERSION))
KV_MAJOR = $(word 1,$(KV_S))
KV_MINOR = $(word 2,$(KV_S))
KV_PATCH = $(word 3,$(KV_S))

# flags to be passed to clang for compiling C files.
CFLAGS := -O2 -g -Wall -Werror \
	 	  -DLINUX_VERSION_MAJOR=$(KV_MAJOR) \
		  -DLINUX_VERSION_MINOR=$(KV_MINOR) \
		  -DLINUX_VERSION_PATCH=$(KV_PATCH) \
		  $(CFLAGS)

# architecture of the system.
ARCH := $(shell uname -m | sed 's/x86_64/amd64/g; s/aarch64/arm64/g')

# project dependencies
DEPENDENCIES:=golang clang-12 llvm-12 libelf-dev libbpf-dev linux-tools-$(shell uname -r) linux-headers-$(shell uname -r)

# package manager
PKG_MGR=apt-get 

# recipe for listing available commands.
help:
	@echo "make build - builds the project"
	@echo "make run - start the application"
	@echo "make dev_run - builds and starts the application"
	@echo "make install - installs the project dependencies"
	@echo "make uinstall - uinstalls the project dependencies"
	@echo "make bpf_helpers - generates the header files"
	@echo "make lint - analyze the project code"
	@echo "make file FILE_PATH=</your/file/path/filename.ext> - create a file with copyrights and license comments"
	@echo "make clean - deletes all object files(*.o)"
	@echo "make help - prints the available commands"

# recipe for running all 'go generate' commands in the project.
gen: export CURR_ARCH := $(ARCH)
gen: export BPF_CFLAGS := $(CFLAGS)
gen:
	go generate ./...

# recipe for Building the Project
build: gen
	go build -o ./$(EXECUTABLE)/ ./cmd/...

# recipe to start the application
run: execute

# recipe to build and start the application
dev_run: build execute

# recipe to execute the executable file
execute: export LINUX_VERSION_MAJOR := $(KV_MAJOR)
execute: export LINUX_VERSION_MINOR := $(KV_MINOR)
execute: export LINUX_VERSION_PATCH := $(KV_PATCH)
execute:
	./$(EXECUTABLE)/$(EXECUTABLE_FILE)

# recipe to install project dependencies
install:
	$(PKG_MGR) -y update && \
	$(PKG_MGR) -y install  $(DEPENDENCIES)

# recipe to uninstall project dependencies
uninstall:
	$(PKG_MGR) -y remove $(DEPENDENCIES)

# recipe to copy the C program dependent header files.
headers: vmlinux bpf_helpers

# recipe to generate the vmlinux.h file
vmlinux:
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(HEADERS_PATH)/vmlinux.h

# recipe to copy the bpf_helper header files from system into /headers folder
bpf_helpers:
	@for file in $(HEADERS_FILES) ; do \
		cp /usr/include/bpf/$${file}.h $(HEADERS_PATH)/$${file}.h; \
	done

# run go fmt against code.
fmt: 
	go fmt ./...

# run go vet against code.
vet: 
	go vet ./...

lint: fmt vet
	revive -formatter stylish -config .revive.toml ./pkg/...
	staticcheck ./...

.PHONY: clean file

# recipe to create a file with license and copyright details.
file:
ifeq ($(FILE_PATH),)
	@echo "ERROR: Please provide a valid file path using 'make $@ FILE_PATH=/your/file/path/filename.ext'"
	@exit 1
endif
	@if [ -e "$(FILE_PATH)" ]; then \
		echo "ERROR: File already exists at $(FILE_PATH)"; \
		exit 1; \
	else \
		echo "Creating file: $(FILE_PATH)" && echo "// SPDX-License-Identifier: Apache-2.0 \n// Copyright $(shell date +'%Y') Authors of Tarian & the Organization created Tarian" > $(FILE_PATH); \
		echo "File created successfully at path: $(shell realpath $(FILE_PATH))"; \
	fi

# recipe to remove all object files(*.o)
clean:
	find -type f -name *.o -delete