#!/bin/bash
# Aegis Benchmarking Test Runner
# This script runs the comprehensive benchmark suite for the Aegis eBPF firewall

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "Aegis eBPF Firewall Benchmark Suite"
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}ERROR: This script must be run as root or with sudo${NC}"
    echo "Usage: sudo ./run_benchmarks.sh [benchmark_name]"
    exit 1
fi

# Change to agent directory
cd "$(dirname "$0")/agent" || exit 1

# Check if vmlinux.h exists
if [ ! -f "src/bpf/vmlinux.h" ]; then
    echo -e "${YELLOW}Generating vmlinux.h for your kernel...${NC}"
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
    echo -e "${GREEN}vmlinux.h generated${NC}"
fi

# Run a specific benchmark
if [ $# -eq 1 ]; then
    BENCHMARK=$1
    echo -e "${BLUE}Running benchmark: ${BENCHMARK}${NC}\n"
    cargo test "${BENCHMARK}" -- --ignored --nocapture
else
    # Run all benchmarks
    echo -e "${BLUE}Running all benchmarks...${NC}"
    
    echo -e "\n${YELLOW}1/5: Attack Scenario (Dropped Packets)${NC}"
    cargo test benchmark_attack_scenario_dropped_packets -- --ignored --nocapture
    
    echo -e "\n${YELLOW}2/5: Legitimate Traffic (Accepted Packets)${NC}"
    cargo test benchmark_legitimate_traffic_accepted_packets -- --ignored --nocapture
    
    echo -e "\n${YELLOW}3/5: Mixed Traffic (Attack + Legitimate)${NC}"
    cargo test benchmark_mixed_traffic -- --ignored --nocapture
    
    echo -e "\n${YELLOW}4/5: Map Operations Performance${NC}"
    cargo test benchmark_map_operations -- --ignored --nocapture
    
    echo -e "\n${YELLOW}5/5: Scalability with Varying Map Sizes${NC}"
    cargo test benchmark_scalability_varying_map_sizes -- --ignored --nocapture
fi

echo -e "\n${GREEN}"
echo "Benchmark Suite Complete!"
echo -e "${NC}"

echo -e "${BLUE}For detailed benchmark documentation, see:${NC}"
echo -e "  - BENCHMARKING.md"
echo -e "  - README.md (Performance & Benchmarks section)"
