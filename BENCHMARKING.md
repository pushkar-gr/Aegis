# Aegis Benchmarking Guide

This document provides a comprehensive guide to benchmarking the Aegis eBPF firewall performance.

## Overview

Aegis includes a benchmarking suite that measures:
- **Latency**: Per packet processing time in nanoseconds
- **Throughput**: Number of packets processed per second
- **Map Operations**: Performance of eBPF map insert/lookup/delete operations
- **Scalability**: Performance impact of varying session map sizes

## Prerequisites

### System Requirements
- Linux kernel with eBPF/XDP support (kernel 5.0+)
- Root or CAP_BPF privileges
- BPF development tools installed

### Installation
```bash
# Install required dependencies
sudo apt-get update
sudo apt-get install -y \
    clang llvm libbpf-dev libelf-dev \
    pkg-config linux-tools-generic \
    build-essential protobuf-compiler

# Generate vmlinux.h for your kernel
cd agent
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
```

## Available Benchmarks

### 1. Attack Scenario (Dropped Packets)

Tests packet processing performance when handling traffic with all malicious packets. All packets should be dropped

- 1,000,000 packets from random, unauthorized IP addresses
- 5,000 authorized sessions pre-filled in the map
- All packets should be dropped (XDP_DROP)
- Simulates DDoS or port scanning attacks

**Run:**
```bash
sudo -E cargo test benchmark_attack_scenario_dropped_packets -- --ignored --nocapture
```
or
```bash
sudo ./run_benchmarks.sh benchmark_attack_scenario_dropped_packets 
```

**Expected Output:**
```
BENCHMARK: Attack Scenario (Dropped Packets)
Pre-filled session map with 5000 entries
 Generating 100 unique random packets...
 Map contains 5000 authorized sessions

 Running benchmark: 100 unique packets x 10000 repeats each
 ATTACK SCENARIO RESULTS
  Average Latency:  39.37 ns/packet
  Throughput:       25400051 packets/sec
  Map Size:         5000 sessions
  Packets Tested:   1000000 (all dropped)
  Status:           PASS (< 2µs)
```

### 2. Legitimate Traffic (Accepted Packets)

Tests packet processing performance when handling legitimate, authorized traffic.

- 1,000,000 packets from authorized IP addresses
- 5,000 authorized sessions pre-filled in the map
- All packets should be accepted (XDP_PASS)
- Simulates normal operational load

**Run:**
```bash
sudo -E cargo test benchmark_legitimate_traffic_accepted_packets -- --ignored --nocapture
```
or
```bash
sudo ./run_benchmarks.sh benchmark_legitimate_traffic_accepted_packets 
```

**Expected Output:**
```
BENCHMARK: Legitimate Traffic (Accepted Packets)
Pre-filled session map with 5000 entries
 Generating 100 unique valid packets...
 Map contains 5000 authorized sessions

 Running benchmark: 100 unique packets x 10000 repeats each...
 LEGITIMATE TRAFFIC RESULTS
  Average Latency:  93.72 ns/packet
  Throughput:       10670081 packets/sec
  Map Size:         5000 sessions
  Packets Tested:   1000000 (all accepted)
  Status:           PASS (< 2µs)
```

### 3. Mixed Traffic

Tests realistic scenario combining both legitimate and attack traffic.

- 1,000,000 total packets (50% legitimate, 50% attack)
- 5,000 authorized sessions pre-filled in the map
- Random IP generation for attack traffic
- Authorized IPs for legitimate traffic
- Tests map lookup performance under mixed load

**Run:**
```bash
sudo -E cargo test benchmark_mixed_traffic -- --ignored --nocapture
```
or
```bash
sudo ./run_benchmarks.sh benchmark_mixed_traffic 
```

**Expected Output:**
```
BENCHMARK: Mixed Traffic (Attack + Legitimate)
Pre-filled session map with 5000 entries
 Testing with 1000000 packets (50% legitimate, 50% attack)
 Map contains 5000 authorized sessions

 MIXED TRAFFIC RESULTS
  Average Latency:  64.98 ns/packet
  Throughput:       15389351 packets/sec
  Map Size:         5000 sessions
  Packets Tested:   1000000
  Status:           PASS (< 2µs)
```

### 4. Map Operations Benchmark

Benchmarks the performance of eBPF map operations (insert, lookup, delete).

- 5,000 operations of each type
- Measures userspace-to-kernel map operation latency
- Reports throughput for each operation type

**Run:**
```bash
sudo -E cargo test benchmark_map_operations -- --ignored --nocapture
```
or
```bash
sudo ./run_benchmarks.sh benchmark_map_operations
```

**Expected Output:**
```
BENCHMARK: eBPF Map Operations Performance
 MAP OPERATIONS RESULTS
  Operations:       5000 per test

  Insert Latency:   0.74 µs/op
  Insert Throughput: 1352162 ops/sec

  Lookup Latency:   0.71 µs/op
  Lookup Throughput: 1409057 ops/sec

  Delete Latency:   0.52 µs/op
  Delete Throughput: 1933973 ops/sec
```

### 5. Scalability Benchmark

Tests performance impact of varying session map sizes.

- Tests map sizes: 100, 500, 1000, 2500, 5000 entries
- Measures latency and throughput for each size
- Helps identify performance degradation at scale

**Run:**
```bash
sudo -E cargo test benchmark_scalability_varying_map_sizes -- --ignored --nocapture
```
or
```bash
sudo ./run_benchmarks.sh benchmark_scalability_varying_map_sizes 
```

**Expected Output:**
```
BENCHMARK: Scalability with Varying Map Sizes
Pre-filled session map with 100 entries
  Map Size:   100 → Latency: 812.75 ns/pkt | Throughput:    1230387 pkt/s
Pre-filled session map with 500 entries
  Map Size:   500 → Latency: 811.73 ns/pkt | Throughput:    1231933 pkt/s
Pre-filled session map with 1000 entries
  Map Size:  1000 → Latency: 618.88 ns/pkt | Throughput:    1615818 pkt/s
Pre-filled session map with 2500 entries
  Map Size:  2500 → Latency: 1006.97 ns/pkt | Throughput:     993082 pkt/s
Pre-filled session map with 5000 entries
  Map Size:  5000 → Latency: 600.36 ns/pkt | Throughput:    1665664 pkt/s
 Scalability benchmark complete
```

## Running All Benchmarks

To run all benchmarks at once:

```bash
cd agent
sudo -E cargo test -- --ignored --nocapture
```

or

```bash
sudo ./run_benchmarks.sh
```

This will execute all benchmark tests sequentially.

## Interpreting Results

### Latency
- **Target**: < 2000 ns (< 2µs) per packet
- **Excellent**: < 100 ns
- **Good**: 100-500 ns
- **Acceptable**: 500-2000 ns
- **Poor**: > 2000 ns

Lower latency means faster packet processing and less CPU overhead.

### Throughput
- Measured in packets per second (pkt/s)
- Higher is better
- Modern XDP programs can achieve 10M+ pkt/s on commodity hardware
- Depends heavily on CPU, NIC, and kernel version

### Map Operations
- Insert operations are typically slower than lookups
- LRU hash maps provide automatic eviction of old entries
- Lookups should be fast (< 5µs)

## Benchmark Design Principles

The benchmarks are designed to:

1. **Replicate Real World Scenarios**: Use random IPs and realistic traffic patterns
2. **Pre fill Maps**: Ensure the map contains entries before testing, simulating production environments
3. **Measure Multiple Metrics**: Both latency and throughput for comprehensive analysis
4. **Test Edge Cases**: Attack scenarios, legitimate traffic, and mixed loads
5. **Ensure Reproducibility**: Use deterministic pseudo-random generators for consistent results

## Contributing

When adding new benchmarks:

1. Follow the existing naming convention: `benchmark_<scenario_name>`
2. Add `#[ignore]` attribute so benchmarks don't run by default
3. Include comprehensive output with measurements
4. Document the benchmark characteristics in this file
5. Ensure deterministic behavior for reproducibility

## Performance Comparison

| Scenario | Avg Latency | Throughput | Pass Rate |
|----------|-------------|------------|-----------|
| Attack (Dropped) | ~39 ns | 25.4M pkt/s | 100% |
| Legitimate (Accepted) | ~94 ns | 10.7M pkt/s | 100% |
| Mixed (50/50) | ~65 ns | 15.4M pkt/s | 100% |

*Results from Intel Core i7, 4.7 GHz, Linux 6.12*
