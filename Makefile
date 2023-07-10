EXECUTABLE=bin

# CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
ARCH := $(shell uname -m | sed 's/x86_64/amd64/g; s/aarch64/arm64/g')

gen: export CURR_ARCH := $(ARCH)
gen: export BPF_CFLAGS := $(CFLAGS)
gen:
	go generate ./...

build: gen
	go build -o ./$(EXECUTABLE)/ ./cmd/...

fmt: ## Run go fmt against code.
	go fmt ./...

vet: ## Run go vet against code.
	go vet ./...

lint: fmt vet
	revive -formatter stylish -config .revive.toml ./pkg/...
	staticcheck ./...

