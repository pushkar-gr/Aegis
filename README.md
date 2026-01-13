# 🛡️ Aegis

**High-Performance Zero Trust Network Controller**

Aegis is a distributed, kernel-bypass firewall designed to enforce **Identity-Based Micro-Segmentation**. Unlike traditional firewalls that rely on static IP rules, Aegis operates on a "Default Drop" posture, dynamically opening ephemeral network paths only after a user has authenticated via a secure Control Plane.

### 🚀 Key Features

* **Kernel-Bypass Speed:** Uses **eBPF/XDP** (C) to filter packets at the network driver level, before OS memory allocation.
* **Distributed Architecture:** Decouples the **Control Plane** (Go/gRPC) from the **Edge Data Plane** (Rust/libbpf-rs).
* **Granular Access Control:** Enforces strictly defined `User IP -> Service IP:Port` pathways.
* **Automated Lifecycle:** The Edge Agent ("The Reaper") automatically revokes rules after 60 seconds of inactivity without central coordination.

### 🛠️ Tech Stack

* **Control Plane:** Go (Golang), gRPC, SQLite.
* **Edge Agent:** Rust, libbpf-rs, Tokio, Tonic.
* **Kernel Hook:** C (eBPF XDP).
