#include "vmlinux.h"
#include "aegis.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "GPL";

/* Protocol Constants */
#define ETH_P_IP 0x0800
#define ETH_P_ARP 0x0806
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/**
 * @brief Configuration Constants
 *
 * Dynamic configuration of controller ip:port and lazy update timeout
 */
volatile const __u32 CONTROLLER_IP;   // Big Endian (Network Byte Order)
volatile const __u16 CONTROLLER_PORT; // Little Endian (Host Byte Order)
volatile const u64
    LAZY_UPDATE_TIMEOUT; // Minimum time delta (ns) before updating last_seen.

struct session_key _session_key = {0};
struct session_val _session_val = {0};

/**
 * @brief Session Map
 * * BPF_MAP_TYPE_LRU_HASH: Least Recently Used eviction.
 * Stores authorized sessions pushed by the Userspace Agent.
 */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 10240); // Support up to 10k concurrent flows
  __type(key, session_key);
  __type(value, session_val);
} session SEC(".maps");

/**
 * @brief XDP Drop Program
 *
 * This function hooks into the XDP (eXpress Data Path) at the network driver
 * level. It parses incoming packets to filter traffic based on a simple
 * allowlist:
 *
 * 1. Pass ARP packets (essential for L2 discovery).
 * 2. Drop non-IPv4 packets.
 * 3. Pass IPv4 TCP/UDP packets matching CONTROLLER_IP and CONTROLLER_PORT.
 * 4. Pass traffic from allowed IPs to allowed services.
 * 4. Drop everything else.
 *
 * @param ctx Context containing packet data pointers.
 * @return XDP_PASS to accept the packet, XDP_DROP to discard it.
 */
SEC("xdp") int xdp_drop_prog(struct xdp_md *ctx) {
  // Initialize data pointers for packet parsing
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // 1. Ethernet Header Parsing
  struct ethhdr *eth = data;

  // VERIFIER: ensure ethernet header is within packet limits
  if ((void *)(eth + 1) > data_end) {
    return XDP_DROP;
  }

  // ALLOWLIST: Always pass ARP to maintain network connectivity
  if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
    return XDP_PASS;
  }

  // PROTOCOL CHECK: Drop non-IPv4 traffic
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return XDP_DROP;
  }

  // 2. IPv4 Header Parsing
  struct iphdr *iph = (void *)(eth + 1);

  // VERIFIER: ensure IP header is within packet limits
  if ((void *)(iph + 1) > data_end) {
    return XDP_DROP;
  }

  __u16 dst_port = 0;

  // 3. Transport Layer Parsing (TCP/UDP)
  if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr *tcph = (void *)(iph + 1);
    // VERIFIER: ensure TCP header fits
    if ((void *)(tcph + 1) > data_end) {
      return XDP_DROP;
    }
    dst_port = bpf_ntohs(tcph->dest);
  } else if (iph->protocol == IPPROTO_UDP) {
    struct udphdr *udph = (void *)(iph + 1);
    // VERIFIER: ensure UDP header fits
    if ((void *)(udph + 1) > data_end) {
      return XDP_DROP;
    }
    dst_port = bpf_ntohs(udph->dest);
  } else {
    // DROP: Block ICMP and other non-transport protocols
    return XDP_DROP;
  }

  // 4. Policy Enforcement
  // Check if traffic is destined for the Controller
  if (dst_port == CONTROLLER_PORT && iph->daddr == CONTROLLER_IP) {
    return XDP_PASS;
  }

  // Check if the source IP and dest IP:Port tuple exists in the allowed map.
  struct session_key key = {0};
  key.src_ip = iph->saddr;
  key.dest_ip = iph->daddr;
  key.dest_port = dst_port;

  struct session_val *val = bpf_map_lookup_elem(&session, &key);
  if (val) {
    // MATCH: Update telemetry timestamp for the "Reaper" (Idle Timeout)
    u64 now = bpf_ktime_get_ns();
    if (now - val->last_seen_ns >= LAZY_UPDATE_TIMEOUT) {
      val->last_seen_ns = now;
    }
    return XDP_PASS;
  }

  // DEFAULT DENY: Drop all other traffic
  return XDP_DROP;
}
