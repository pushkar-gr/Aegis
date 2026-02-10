CONTROLLER_DIR := controller
AGENT_DIR := agent
PROTO_SRC_DIR := proto
BIN_DIR := bin

DOCKER_COMPOSE_TEST := deploy/docker-compose.test-ip-change.yml
DOCKER_COMPOSE_MAIN := deploy/docker-compose.yml

.PHONY: all build build-go build-rust run clean proto deps-proto vmlinux test test-go test-rust docker-build up down logs test-ip-up test-ip-steal test-ip-down

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
		echo "Error: cargo not found. Please install Rust."; \
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

# Install required Go plugins for Protoc
deps-proto:
	@echo "Installing protoc plugins..."
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Generate Go code from .proto files
proto:
	@echo "Checking for protoc plugins..."
	@if ! command -v protoc-gen-go >/dev/null 2>&1 || ! command -v protoc-gen-go-grpc >/dev/null 2>&1; then \
		echo "Protoc plugins not found. Running 'make deps-proto'..."; \
		$(MAKE) deps-proto; \
	fi
	@echo "Generating Go Protocol Buffers..."
	protoc --go_out=./$(CONTROLLER_DIR) --go_opt=paths=source_relative \
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
	@if [ -z "$(BPFTOOL)" ]; then \
		echo "Error: bpftool not found. Please install it (e.g., apt install linux-tools-common)"; \
		exit 1; \
	fi
	@echo "Generating vmlinux.h..."
	@mkdir -p $(AGENT_DIR)/src/bpf
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(AGENT_DIR)/src/bpf/vmlinux.h
	@echo "vmlinux.h generated at $(AGENT_DIR)/src/bpf/vmlinux.h"

# Normal Compose Build with no cache
docker-build:
	docker compose -f $(DOCKER_COMPOSE_MAIN) build --no-cache

# Normal Compose Up
up:
	docker compose -f $(DOCKER_COMPOSE_MAIN) up -d --build

# Normal Compose Down
down:
	docker compose -f $(DOCKER_COMPOSE_MAIN) down

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
