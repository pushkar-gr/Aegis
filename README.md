# Aegis

**High-Performance Zero Trust Network Controller**

![License](https://img.shields.io/badge/License-AGPL_3.0-blue.svg)
![Build Status](https://github.com/pushkar-gr/aegis/actions/workflows/ci.yml/badge.svg)
![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=flat&logo=rust&logoColor=white)
![Go](https://img.shields.io/badge/go-%2300ADD8.svg?style=flat&logo=go&logoColor=white)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey)

Aegis is a distributed, kernel bypass firewall designed to enforce **Identity-Based Micro-Segmentation** using **eBPF** technology. It is lightweight, efficient, and can be directly **deployed in a router** or edge gateway. Unlike traditional firewalls that rely on static IP rules, Aegis operates on a "Default Drop" posture, dynamically opening ephemeral network paths only after a user has authenticated via a secure Control Plane.

Designed for **Network Security**, Aegis bridges the gap between Identity Providers (IdP) and raw network enforcement. It transforms your network gateway into an identity aware enforcement point.

### Where to use it
* **Critical Infrastructure:** Micro-segment sensitive assets like Databases, SSH Jump Hosts, and Internal Dashboards.
* **Zero Trust Migration:** Replace static firewall rules (IP-whitelisting) with dynamic, ephemeral access based on user identity.

### How it works
1.  **Deploy:** Run the **Controller** centrally and the **Agent** on your network gateway (router/server).
2.  **Configure:** Define protected Services (IP:Port) and User Roles via the Admin UI.
3.  **Connect:** Users authenticate via the Web Portal and click to "activate" a service.
4.  **Enforce:** The Agent instantly updates kernel-level eBPF maps to allow traffic *only* from that user to that service for till the user is active.

## Architecture

There are two components, **Control Plane** (User Authentication and Policy) and a **Data Plane** (Packet Enforcement).

1.  **Authentication:** Clients access the **Controller** (in the Private Zone) to authenticate via a web interface.
2.  **Policy Dispatch:** After a valid login, the Controller pushes a signed "session" to the **Agent** via gRPC.
3.  **Enforcement:** The **Agent** (Gateway) updates its eBPF maps in the kernel, instantly allowing traffic from that specific user IP to the requested service.
4.  **Auto-Revocation:** If the user becomes inactive, the Agent automatically purges the rule, closing the firewall hole.

[![](https://mermaid.ink/img/pako:eNqlV3lvm0gU_yojoiiORAhgDhulkXwkrbWO7fXR7rZerQYYbGQMaMBt0jTffd_MALZxWrVb_IeZd_zem3fN8Cx5iU8kRzo_fw7jMHfQ80W-Jlty4aALH9PNhYwE4T2mIXYjkgHnWfAeQBVWOd0RkHKxt1nRZBf7TPdMI-zH1FMabjF9mpPHvJdECeVsorIfY0dhTPZ03HZtz2L0IInzWfiVe6JZ6ePFy8vL-fkyDqLki7fGNEfz7jJG8Jyfo6urK_RxPLpDHQdNFt3hoMdIgp3t3BXF6RpNdm4Uep-W0sckJlySE9AgzgmNSb6U_hEa7FlkhDYaS4n9o2vUi0ISg8Tl5V6kk-ewZ0IBcRHjXb5OKPjro46XJ7QCI7G_jE8d7TloOl7M76avODpNdjmH5Y4ySU4AN-78FUEjiPuRr35IiZeHSVyFhD37twr4D7bPaJZijwC6WCG-PMJjz12-VkGGxyYAAQcRoNy49LYxiFeUZNnlic5f_Qmo3Li38ILeJcnm5tq9ZSoTFqcc3YcR20ajd6randw_4PRTg6sTWCFYluqdCHKOhmHGEnCgeBDaV-LHMldulWfx9Y12VpBY4fZ0l-ViXVpeTSe9Kvd1yz_IbheKazp435nfvVaHNPyMc1Lml8kKSlGJOEIjkn9J6Ob_ZbkHnUOTaBLhmBkploivT7ZfcCNebxCDt8kB6SgMM0I_s-yZqmpql4z8gbhoMUCNltpST1Pa7xbpnP05DGFz_S6DeyWDp1thpkKeOFCf0CSHjUNjFeTSqwZRVgqazd7JiHnSSdPLH3TdfNq5v4e5cD8cfxBJqdiagoqaRg2oNTSnOAhCr2h1XjsAsJRA7oCNGsNkFcbXhVdgG6RueeMIxXI-oCsFlB8wzJow2WWlPsgrR_KVP7pSdCoURuKBW2G8Qg1R1YVTTIubg1YTFNZz3MshNN4uRYNJ4ZBorZqJpoLu4iChHoz2OIfJwtDBTA1LxwrqkwzOhYOiYKEXLdmBoXfdmQzKve-F6jiuAg2de2sHdYaQAI4hgGvhK5Y1dw1wgyYpYhH3BFVsS8R2lAj0IqRMtBvGjQZ7KSd25Qu8_NufjsvwFMK1aumNR_PpeIgmww4b1uOHh8Vo0OvMB-NRrXhMZd-2sxy6WHD2oUA3YObbUpoQmsEIK4Skb9AQtV1aipg-oJxQP4wx7_YG677LE9Q3b2AvkMZZTgneokXqA2xWSkvAvxVoRTFyYB4ACKaQZjO2ViRHQZjN_x4ORm_3I8yLcJb1SYBScXIGYRQ5Z5quubohZ-DZhjhnho7NwCyWV19CP187evooe-yQd86CIKiBUXG6CTDdaurNVgUWBNjWrV8AS4tRWrjm6qbmVmiW5boW_gW0TcbOjAKsaRu2EVRgpmERuwamAVhB8HEGtxSKnxxkIrM04XlezcTuBybsVltte79twku2KZw0kH9hRfUNG2v7qBiuGVinVr4bFd8tgAxTt7FaAbnNtu-7vwLEelpAubbmaV4FRQKzaapHmge6fCbL1XwV1XjILy5MorIOGeVJW5TJIevgclTk_RSxulMUaTuU2PemzJtNLkaZzGa1zMZPlYdDtX5XLkaZ7x7RxVziMTroy2EYb6Dnn6JqWMPbhhEI8kmAd1GOyiCKy_RJudfVVPST_SHYzAt-Jr6lhMR1MA3VUlgHY-oic2hK_Lq69TPq_Ch4Rdn-HeX2PmyuYbu1rmt-r-sYJL8eTXY0jYgkSysa-pLDv4qkLaFbzJbSM7O3lPi31FJy4JV9Qi2lZfwCOimOPybJtlSDul2tJSfAUQarHR_W_RDD9W4vAjccQnvwvZVLjtXmEJLzLD1KzpWhqUpTVe2Wppuy9ASUtmLp8FNt0zYMS2-1X2TpKzeoKXpbb9mm2mrDNa6pGy1ZIn4IXzAP4suQfyC-_AeaJVfe?type=png)](https://mermaid.live/edit#pako:eNqlV3lvm0gU_yojoiiORAhgDhulkXwkrbWO7fXR7rZerQYYbGQMaMBt0jTffd_MALZxWrVb_IeZd_zem3fN8Cx5iU8kRzo_fw7jMHfQ80W-Jlty4aALH9PNhYwE4T2mIXYjkgHnWfAeQBVWOd0RkHKxt1nRZBf7TPdMI-zH1FMabjF9mpPHvJdECeVsorIfY0dhTPZ03HZtz2L0IInzWfiVe6JZ6ePFy8vL-fkyDqLki7fGNEfz7jJG8Jyfo6urK_RxPLpDHQdNFt3hoMdIgp3t3BXF6RpNdm4Uep-W0sckJlySE9AgzgmNSb6U_hEa7FlkhDYaS4n9o2vUi0ISg8Tl5V6kk-ewZ0IBcRHjXb5OKPjro46XJ7QCI7G_jE8d7TloOl7M76avODpNdjmH5Y4ySU4AN-78FUEjiPuRr35IiZeHSVyFhD37twr4D7bPaJZijwC6WCG-PMJjz12-VkGGxyYAAQcRoNy49LYxiFeUZNnlic5f_Qmo3Li38ILeJcnm5tq9ZSoTFqcc3YcR20ajd6randw_4PRTg6sTWCFYluqdCHKOhmHGEnCgeBDaV-LHMldulWfx9Y12VpBY4fZ0l-ViXVpeTSe9Kvd1yz_IbheKazp435nfvVaHNPyMc1Lml8kKSlGJOEIjkn9J6Ob_ZbkHnUOTaBLhmBkploivT7ZfcCNebxCDt8kB6SgMM0I_s-yZqmpql4z8gbhoMUCNltpST1Pa7xbpnP05DGFz_S6DeyWDp1thpkKeOFCf0CSHjUNjFeTSqwZRVgqazd7JiHnSSdPLH3TdfNq5v4e5cD8cfxBJqdiagoqaRg2oNTSnOAhCr2h1XjsAsJRA7oCNGsNkFcbXhVdgG6RueeMIxXI-oCsFlB8wzJow2WWlPsgrR_KVP7pSdCoURuKBW2G8Qg1R1YVTTIubg1YTFNZz3MshNN4uRYNJ4ZBorZqJpoLu4iChHoz2OIfJwtDBTA1LxwrqkwzOhYOiYKEXLdmBoXfdmQzKve-F6jiuAg2de2sHdYaQAI4hgGvhK5Y1dw1wgyYpYhH3BFVsS8R2lAj0IqRMtBvGjQZ7KSd25Qu8_NufjsvwFMK1aumNR_PpeIgmww4b1uOHh8Vo0OvMB-NRrXhMZd-2sxy6WHD2oUA3YObbUpoQmsEIK4Skb9AQtV1aipg-oJxQP4wx7_YG677LE9Q3b2AvkMZZTgneokXqA2xWSkvAvxVoRTFyYB4ACKaQZjO2ViRHQZjN_x4ORm_3I8yLcJb1SYBScXIGYRQ5Z5quubohZ-DZhjhnho7NwCyWV19CP187evooe-yQd86CIKiBUXG6CTDdaurNVgUWBNjWrV8AS4tRWrjm6qbmVmiW5boW_gW0TcbOjAKsaRu2EVRgpmERuwamAVhB8HEGtxSKnxxkIrM04XlezcTuBybsVltte79twku2KZw0kH9hRfUNG2v7qBiuGVinVr4bFd8tgAxTt7FaAbnNtu-7vwLEelpAubbmaV4FRQKzaapHmge6fCbL1XwV1XjILy5MorIOGeVJW5TJIevgclTk_RSxulMUaTuU2PemzJtNLkaZzGa1zMZPlYdDtX5XLkaZ7x7RxVziMTroy2EYb6Dnn6JqWMPbhhEI8kmAd1GOyiCKy_RJudfVVPST_SHYzAt-Jr6lhMR1MA3VUlgHY-oic2hK_Lq69TPq_Ch4Rdn-HeX2PmyuYbu1rmt-r-sYJL8eTXY0jYgkSysa-pLDv4qkLaFbzJbSM7O3lPi31FJy4JV9Qi2lZfwCOimOPybJtlSDul2tJSfAUQarHR_W_RDD9W4vAjccQnvwvZVLjtXmEJLzLD1KzpWhqUpTVe2Wppuy9ASUtmLp8FNt0zYMS2-1X2TpKzeoKXpbb9mm2mrDNa6pGy1ZIn4IXzAP4suQfyC-_AeaJVfe)

## Key Features

* **Kernel Bypass Speed:** Uses **eBPF/XDP** (C) to filter packets at the network driver level, occurring before the OS handles memory allocation.
* **Distributed Design:** Decouples the **Control Plane** (Go/gRPC) from the **Edge Data Plane** (Rust/libbpf-rs) for scalability.
* **Granular Access Control:** Enforces strict `User IP -> Service IP:Port` pathways. No broad network access is granted.
* **Automated Lifecycle:** The Edge Agent automatically revokes rules after 60 seconds of inactivity, preventing stale permissions.

## Tech Stack

* **Control Plane:** Go (Golang 1.25), gRPC, SQLite.
* **Edge Agent:** Rust, libbpf-rs, Tokio, Tonic.
* **Kernel Hook:** C (eBPF XDP).
> NOTE: frontend for this project was completly written by gemini.

## Documentation & Setup

Aegis is split into two components. Refer to their respective directories for detailed build and configuration instructions.

> Default login: username `root`, password `root`.

| Component | Description | Docs |
| :--- | :--- | :--- |
| **Controller** | The central authority handling authentication (SSO), policy management, and distributing rules to agents. | [Controller Docs](./controller/README.md) |
| **Agent** | The edge node daemon running on routers/servers. It attaches eBPF programs to network interfaces and enforces rules. | [Agent Docs](./agent/README.md) |

## Quick Start (Docker Compose)

For a local setup with Controller, Agent, and simulated Client/Service zones:

```bash
docker-compose -f deploy/docker-compose.yml up --build -d
```

### Performance & Benchmarks

Aegis is optimized for extreme low latency environments and minimal footprint. Read detailed benchmarks results in [Benchmarking Docs](./BENCHMARKING.md)

**Reproduce Benchmarks:**

To run all comprehensive benchmarks (requires root for XDP hook):
```bash
cd agent
sudo -E cargo test -- --ignored --nocapture
```

or

```bash
sudo ./run_benchmarks.sh
```

**Available Benchmarks:**

1. **Attack Scenario** - Tests packet processing when all traffic is malicious (dropped)
   ```bash
   sudo -E cargo test benchmark_attack_scenario_dropped_packets -- --ignored --nocapture
   ```

2. **Legitimate Traffic** - Tests packet processing when all traffic is authorized (accepted)
   ```bash
   sudo -E cargo test benchmark_legitimate_traffic_accepted_packets -- --ignored --nocapture
   ```

3. **Mixed Traffic** - Tests realistic scenario with 50% legitimate and 50% attack traffic
   ```bash
   sudo -E cargo test benchmark_mixed_traffic -- --ignored --nocapture
   ```

4. **Map Operations** - Benchmarks eBPF map insert/lookup/delete performance
   ```bash
   sudo -E cargo test benchmark_map_operations -- --ignored --nocapture
   ```

5. **Scalability** - Tests performance impact of varying map sizes (100 to 5000 entries)
   ```bash
   sudo -E cargo test benchmark_scalability_varying_map_sizes -- --ignored --nocapture
   ```
**Expected Result:**

```text
BENCHMARK: Attack Scenario (Dropped Packets)
Pre-filled session map with 5000 entries
 Generating 100 unique random packets...
 Map contains 5000 authorized sessions

 Running benchmark: 100 unique packets x 10000 repeats each
 ATTACK SCENARIO RESULTS
  Average Latency:  39.37 ns/packet
  Throughput:       25400051 packets/sec
  Map Size:         5000 sessions
  Packets Tested:   1000000 (all accepted)
  Status:           PASS (< 2µs)
```

To build the optimized binary and check size:

```bash
cargo build --release
```

**Key Features:**
- Random IP generation for realistic traffic simulation
- Pre filled maps to stimulate real world scenarios
- Latency measurements (nanoseconds per packet)
- Throughput measurements (packets per second)

## Future Goals & Improvements

### Advanced Networking & Discovery
* **Dynamic Service Discovery:** Switch from static IP definitions to DNS based hostname resolution (`db-prod.local`), allowing integration with dynamic environments like Kubernetes and Docker Swarm.
* **IPv6 Support:** eBPF/XDP data plane to handle IPv6 headers and routing.

### Enhanced Security Posture
* **Egress Traffic Guard:** Implement Traffic Control (TC) BPF program to filter *outbound* connections. This prevents "Reverse Shell" attacks by making sure protected services cannot initiate unauthorized connections to Command and Control (C2) servers.
* **Layer 7 Deep Packet Inspection (WAF):** Move beyond L3/L4 headers to inspect packet payloads for application layer threats (e.g., SQL Injection, Log4j payloads), combining firewalling with Intrusion Prevention (IPS).

### Identity & Access Management (IAM)
* **OIDC Integration:** Replace local database authentication with OpenID Connect (OIDC) (e.g., Google Workspace, Okta, Azure AD) to enable Multi Factor Authentication (MFA) and centralized user management.
* **Context-Aware Access:** Add policy conditions beyond identity, such as device health (OS version, patch level) or geolocation.

### Enterprise Operations
* **Fleet Management:** decouple the 1:1 Controller-Agent relationship to support a mesh of Edge Routers managed by a single High Availability Controller cluster.
* **Observability Dashboard:** Add Prometheus/Grafana export endpoints to visualize real-time bandwidth usage, dropped packet counts, and active session trends across the network.
