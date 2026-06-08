.PHONY: all build generate clean fmt vet test

BIN_DIR := bin
CMD_DIR := cmd/sqldiag
EBPF_DIR := internal/ebpf

GO ?= go
CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)

all: build

generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate:
	@echo "Generating eBPF bindings..."
	@cd $(EBPF_DIR) && $(GO) generate ./...
	@echo "eBPF bindings generated successfully."

build: generate
	@echo "Building sqldiag..."
	@mkdir -p $(BIN_DIR)
	@$(GO) build -o $(BIN_DIR)/sqldiag $(CMD_DIR)
	@echo "Build completed successfully. Binary: $(BIN_DIR)/sqldiag"

build-linux:
	@echo "Building sqldiag for Linux..."
	@mkdir -p $(BIN_DIR)
	@GOOS=linux GOARCH=amd64 $(GO) build -o $(BIN_DIR)/sqldiag-linux-amd64 $(CMD_DIR)
	@echo "Linux build completed successfully. Binary: $(BIN_DIR)/sqldiag-linux-amd64"

fmt:
	@echo "Formatting Go code..."
	@$(GO) fmt ./...

vet:
	@echo "Running go vet..."
	@$(GO) vet ./...

test:
	@echo "Running tests..."
	@$(GO) test ./...

clean:
	@echo "Cleaning..."
	@rm -rf $(BIN_DIR)
	@rm -f $(EBPF_DIR)/*.o
	@rm -f $(EBPF_DIR)/mysql_bpfel.go
	@echo "Clean completed."

install: build
	@echo "Installing sqldiag to /usr/local/bin..."
	@sudo cp $(BIN_DIR)/sqldiag /usr/local/bin/
	@echo "Installation completed."

help:
	@echo "Available targets:"
	@echo "  all          - Build everything (default)"
	@echo "  generate     - Generate eBPF bindings using bpf2go"
	@echo "  build        - Build the sqldiag binary"
	@echo "  build-linux  - Cross-compile for Linux amd64"
	@echo "  fmt          - Format Go code"
	@echo "  vet          - Run go vet"
	@echo "  test         - Run tests"
	@echo "  clean        - Clean build artifacts"
	@echo "  install      - Install to /usr/local/bin (requires sudo)"
	@echo "  help         - Show this help message"
