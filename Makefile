# SPDX-License-Identifier: Apache-2.0
# Copyright 2023 Authors of Tarian & the Organization created Tarian

# executable Files Path
EXECUTABLE=bin

# executable File name
EXECUTABLE_FILE = tarian_detector

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

# recipe for listing available commands.
help:
	@echo "make build - builds the project"
	@echo "make run - start the application"
	@echo "make install - installs the project dependencies"
	@echo "make uinstall - uinstalls the project dependencies"
	@echo "make bpf_helpers - generates the header files"
	@echo "make lint - analyze the project code"
	@echo "make module NAME=<module-name> - create ebpf module with basic template. A module is a collection of *.c and *.go file together bascally ebpf with kernelspace and userspace programs."
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


.PHONY: clean file module

# recipe to create a bpf module with basic template. A module is a collection of *.c and *.go file together bascally ebpf with kernelspace and userspace programs.
module: 
ifeq ($(NAME),)
	@echo "ERROR: Please provide a valid module name. \n\n\tUsage: make $@ NAME=__x64_sys_open\n"
	@exit 1
else 
	@if [ -e "$(shell pwd)/pkg/eBPF/c/BPF/$(NAME)" ]; then \
		echo "ERROR: module already exists at $(shell pwd)/pkg/eBPF/c/BPF/$(NAME) and is as follows:\n"; \
		ls "./pkg/eBPF/c/BPF/$(NAME)"; \
	else \
		echo "Creating bpf module: $(shell pwd)/pkg/eBPF/c/BPF/$(NAME)"; \
		mkdir $(shell pwd)/pkg/eBPF/c/BPF/$(NAME); \
		\
		# c template - start	\
		echo "// SPDX-License-Identifier: Apache-2.0\n// Copyright 2023 Authors of Tarian & the Organization created Tarian\n\n//go:build ignore\n" > $(shell pwd)/pkg/eBPF/c/BPF/$(NAME)/$(NAME).bpf.c; \
		echo "#include \"headers.h\"\n" >> $(shell pwd)/pkg/eBPF/c/BPF/$(NAME)/$(NAME).bpf.c; \
		echo "// data gathered by this program \nstruct event_data {\n\tint id;\n\tevent_context_t eventContext;\n};\n" >> $(shell pwd)/pkg/eBPF/c/BPF/$(NAME)/$(NAME).bpf.c; \
		echo "// Force emits struct event_data into the elf\nconst struct event_data *unused __attribute__((unused));\n" >> $(shell pwd)/pkg/eBPF/c/BPF/$(NAME)/$(NAME).bpf.c; \
		echo "// ringbuffer map definition\nBPF_RINGBUF_MAP(event);\n" >> $(shell pwd)/pkg/eBPF/c/BPF/$(NAME)/$(NAME).bpf.c; \
		echo "SEC("")\nint $(NAME)(){\n\tstruct event_data *ed;\n\n\t// allocate space for an event in map.\n\ted = BPF_RINGBUF_RESERVE(event, *ed);\n\tif (!ed) {\n\t\treturn -1;\n\t}\n\n\t// sets the context\n\tset_context(&ed->eventContext);\n\n\t// pushes the information to ringbuf event mamp\n\tBPF_RINGBUF_SUBMIT(ed);\n\n\treturn 0;\n};" >> $(shell pwd)/pkg/eBPF/c/BPF/$(NAME)/$(NAME).bpf.c; \
		# c template - end	\
		\
		# go template - start \
		echo "// SPDX-License-Identifier: Apache-2.0\n// Copyright 2023 Authors of Tarian & the Organization created Tarian\n" > $(shell pwd)/pkg/eBPF/c/BPF/$(NAME)/$(NAME).go; \
		echo "package $(NAME)\n" >> $(shell pwd)/pkg/eBPF/c/BPF/$(NAME)/$(NAME).go; \
		echo "//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags \$$BPF_CFLAGS -type event_data -target \$$CURR_ARCH $(NAME) $(NAME).bpf.c -- -I../../../../../headers -I../../\n" >> $(shell pwd)/pkg/eBPF/c/BPF/$(NAME)/$(NAME).go; \
		echo "type $(NAME) struct{}\n" >> $(shell pwd)/pkg/eBPF/c/BPF/$(NAME)/$(NAME).go; \
		echo "func New$(NAME)() *$(NAME) {\n\treturn &$(NAME){}\n}\n" >> $(shell pwd)/pkg/eBPF/c/BPF/$(NAME)/$(NAME).go; \
		echo "func (ep *$(NAME)) NewEbpf() {}\n\nfunc (ep *$(NAME)) DataParser(data any) {}\n" >> $(shell pwd)/pkg/eBPF/c/BPF/$(NAME)/$(NAME).go; \
		# go template - end \
		echo "module successfully created!\n"; \
		make fmt; \
	fi
endif


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
		echo "Creating file: $(FILE_PATH)" && echo "// SPDX-License-Identifier: Apache-2.0 \n// Copyright 2023 Authors of Tarian & the Organization created Tarian" > $(FILE_PATH); \
	fi


# recipe to remove all object files(*.o)
clean:
	find -type f -name *.o -delete