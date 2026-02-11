CONTROLLER_DIR := controller
AGENT_DIR := agent
PROTO_SRC_DIR := proto
BIN_DIR := bin
PWD := $(shell pwd)
GO_BIN := $(shell go env GOPATH)/bin

DOCKER_COMPOSE_TEST := deploy/docker-compose.test-ip-change.yml
DOCKER_COMPOSE_MAIN := deploy/docker-compose.yml

.PHONY: all build build-go build-rust run clean proto deps-proto vmlinux ci ci-go ci-rust verify-ebpf test test-go test-rust docker-build up down logs test-ip-up test-ip-steal test-ip-down

all: build

build: build-go build-rust

# Build the Controller binary
build-go:
	@echo "Building Controller (Go)..."
	@mkdir -p $(BIN_DIR)
	cd $(CONTROLLER_DIR) && go build -o ../$(BIN_DIR)/controller ./main.go
	@echo "Controller built: $(BIN_DIR)/controller"

# Build the Agent binary
build-rust:
	@echo "Building Agent (Rust)..."
	@mkdir -p $(BIN_DIR)
	@if ! command -v cargo >/dev/null 2>&1; then \
		echo "Error: cargo not found. Install Rust."; \
		exit 1; \
	fi
	@if [ ! -f $(AGENT_DIR)/src/bpf/vmlinux.h ]; then \
		$(MAKE) vmlinux; \
	fi
	cd $(AGENT_DIR) && cargo build --release
	cp $(AGENT_DIR)/target/release/aegis-agent $(BIN_DIR)/agent
	@echo "Agent built: $(BIN_DIR)/agent"

# Clean artifacts
clean:
	@echo "Cleaning up..."
	rm -rf $(BIN_DIR)
	rm -f $(AGENT_DIR)/src/bpf/*.skel.rs
	rm -f $(AGENT_DIR)/src/bpf/vmlinux.h
	cd $(AGENT_DIR) && cargo clean

# Run CI locally
ci: ci-go ci-rust

# Go CI: Lint (Docker), Vuln Check (Docker), Test, Build
ci-go:
	@echo "--- [CI] Starting Go Controller Checks ---"
	@echo "[Lint] Running golangci-lint (via Docker)..."
	docker run --rm -v "$(PWD)/$(CONTROLLER_DIR):/app" -w /app golangci/golangci-lint:latest golangci-lint run -v
	
	@echo "[Vuln] Running govulncheck (via Docker)..."
	docker run --rm -v "$(PWD)/$(CONTROLLER_DIR):/app" -w /app golang:1.25.7 go run golang.org/x/vuln/cmd/govulncheck@latest ./...
	
	@echo "[Test] Running Unit Tests..."
	cd $(CONTROLLER_DIR) && JWT_SECRET="test-secret" go test -v ./...
	
	@echo "[Build] Verifying Build..."
	cd $(CONTROLLER_DIR) && go build -o ../$(BIN_DIR)/controller ./main.go
	@echo "--- [CI] Go Checks Passed ---"

# Rust CI: Format, Build (Gen Skel), Clippy, BPF Verify, Test
ci-rust: vmlinux
	@echo "--- [CI] Starting Rust Agent Checks ---"
	@echo "[Build] Building (Generates .skel.rs)..."
	cd $(AGENT_DIR) && cargo build --verbose
	
	@echo "[Format] Checking formatting..."
	cd $(AGENT_DIR) && cargo fmt -- --check
	
	@echo "[Lint] Running Clippy..."
	cd $(AGENT_DIR) && cargo clippy -- -D warnings
	
	@echo "[Verify] Checking eBPF C-Source Safety (Clang)..."
	$(MAKE) verify-ebpf
	
	@echo "[Test] Running Unit Tests..."
	cd $(AGENT_DIR) && cargo test --verbose
	@echo "--- [CI] Rust Checks Passed ---"

# Helper to verify eBPF compilation (simulates CI verification step)
verify-ebpf:
	@echo "Compiling eBPF source with Clang to verify syntax..."
	cd $(AGENT_DIR) && clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c src/bpf/aegis.bpf.c -o aegis_verify.o
	@echo "eBPF Compilation successful (Artifact: $(AGENT_DIR)/aegis_verify.o)"

# Install required Go plugins for Protoc
deps-proto:
	@echo "Installing protoc plugins..."
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Generate Go code from .proto files
proto:
	@echo "Checking for protoc plugins..."
	@if [ ! -x "$(GO_BIN)/protoc-gen-go" ] || [ ! -x "$(GO_BIN)/protoc-gen-go-grpc" ]; then \
		echo "Protoc plugins not found in $(GO_BIN). Running 'make deps-proto'..."; \
		$(MAKE) deps-proto; \
	fi
	@echo "Generating Go Protocol Buffers..."
	PATH=$(GO_BIN):$$PATH protoc --go_out=./$(CONTROLLER_DIR) --go_opt=paths=source_relative \
	       --go-grpc_out=./$(CONTROLLER_DIR) --go-grpc_opt=paths=source_relative \
	       $(PROTO_SRC_DIR)/*.proto
	@echo "Proto generation complete."

# Run all tests
test: test-go test-rust

# Run Go tests (Controller)
test-go:
	@echo "Running Controller (Go) tests..."
	cd $(CONTROLLER_DIR) && JWT_SECRET="test-secret" go test -v ./...

# Run Rust tests (Agent)
test-rust:
	@echo "Running Agent (Rust) tests..."
	cd $(AGENT_DIR) && cargo test

# Generate vmlinux.h from the running kernel into the Agent's source dir
vmlinux:
	@echo "Generating vmlinux.h..."
	@mkdir -p $(AGENT_DIR)/src/bpf
	@if command -v bpftool >/dev/null 2>&1; then \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(AGENT_DIR)/src/bpf/vmlinux.h; \
	elif [ -f /usr/sbin/bpftool ]; then \
		/usr/sbin/bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(AGENT_DIR)/src/bpf/vmlinux.h; \
	else \
		echo "Error: bpftool not found in PATH or /usr/sbin. Install it."; \
		exit 1; \
	fi
	@echo "vmlinux.h generated at $(AGENT_DIR)/src/bpf/vmlinux.h"

# Normal Compose Build with no cache
docker-build:
	docker compose -f $(DOCKER_COMPOSE_MAIN) build --no-cache

# Normal Compose Up
up:
	docker compose -f $(DOCKER_COMPOSE_MAIN) up -d --build

# Normal Compose Down
down:
	docker compose -f $(DOCKER_COMPOSE_MAIN) --profile "*" down

ip-steal:
	@echo "Stopping protected-service1..."
	docker stop aegis-protected-service1
	@echo "Starting IP stealer..."
	docker compose -f $(DOCKER_COMPOSE_MAIN) up -d ip-stealer
	@echo "Restarting protected-service1 (should get new IP)..."
	docker start aegis-protected-service1

# View Logs
logs:
	docker compose -f $(DOCKER_COMPOSE_MAIN) logs -f

# Start the test environment
test-ip-up:
	docker compose -f $(DOCKER_COMPOSE_TEST) up -d --build controller target-app

# Trigger the IP change (Stop target -> Start stealer -> Start target)
test-ip-steal:
	@echo "Stopping target-app..."
	docker stop target-app
	@echo "Starting IP stealer..."
	docker compose -f $(DOCKER_COMPOSE_TEST) up -d ip-stealer
	@echo "Restarting target-app (should get new IP)..."
	docker start target-app

# Full cleanup for test environment
test-ip-down:
	docker compose -f $(DOCKER_COMPOSE_TEST) --profile "*" down

# Helper to bump version in Cargo.toml and HTML files
bump-version:
	@if [ -z "$(v)" ]; then echo "Usage: make bump-version v=1.1.1"; exit 1; fi
	@echo "Bumping version to $(v)..."
	sed -i 's/^version = ".*"/version = "$(v)"/' $(AGENT_DIR)/Cargo.toml
	sed -i 's/v[0-9.]*-aegis/v$(v)-aegis/' $(CONTROLLER_DIR)/static/pages/*.html
	@echo "Version bumped to $(v)"
