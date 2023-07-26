# executable Files Path
EXECUTABLE=bin

# executable File name
EXECUTABLE_FILE = dev-cli

# header files path in the project.
HEADERS_PATH=headers

# required C header files
HEADERS_FILES = bpf_helpers bpf_helper_defs bpf_endian bpf_core_read bpf_tracing

# flags to be passed to clang for compiling C files.
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

# architecture of the system.
ARCH := $(shell uname -m | sed 's/x86_64/amd64/g; s/aarch64/arm64/g')

# project dependencies
DEPENDENCIES:=golang clang llvm libelf-dev libbpf-dev linux-tools-$(shell uname -r) linux-headers-$(shell uname -r)

# package manager
PKG_MGR=apt-get 

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
	@echo "ERROR: Please provide a valid file path using 'make create_file FILE_PATH=/your/file/path/filename.ext'"
	@exit 1
endif
	@if [ -e "$(FILE_PATH)" ]; then \
		echo "ERROR: File already exists at $(FILE_PATH)"; \
		exit 1; \
	else \
		echo "Creating file: $(FILE_PATH)" && echo "// SPDX-License-Identifier: Apache-2.0 \n// Copyright 2023 Authors of Tarian & the Organization created Tarian" > $(FILE_PATH); \
	fi


# recipe to remove all object files(*.o)
clean:
	find -type f -name *.o -delete