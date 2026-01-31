#include "vmlinux.h"
#include "aegis.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "GPL";

/* Protocol constants */
#define ETH_P_IP 0x0800
#define ETH_P_ARP 0x0806
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/**
 * @brief Configuration Constants
 *
 * Dynamic configuration of controller ip:port and lazy update timeout
 */
volatile const __be32 CONTROLLER_IP;   // Big Endian (Network Byte Order)
volatile const __be16 CONTROLLER_PORT; // Little Endian (Network Byte Order)
volatile const u64
    LAZY_UPDATE_TIMEOUT; // Min time (ns) between timestamp updates
struct session_key _session_key = {0};
struct session_val _session_val = {0};

/**
 * @brief Session Map
 *
 * BPF_MAP_TYPE_LRU_HASH: Least Recently Used eviction.
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
 *
 * Policy:
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

  // Parse Ethernet header
  struct ethhdr *eth = data;

  // Verify header within packet bounds
  if ((void *)(eth + 1) > data_end) {
    return XDP_DROP;
  }

  // Allow ARP for network discovery
  if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
    return XDP_PASS;
  }

  // Drop non-IPv4 traffic
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return XDP_DROP;
  }

  // Parse IPv4 header
  struct iphdr *iph = (void *)(eth + 1);

  // Verify header within packet bounds
  if ((void *)(iph + 1) > data_end) {
    return XDP_DROP;
  }

  __be16 dst_port = 0;

  // Parse transport layer (TCP/UDP)
  if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr *tcph = (void *)(iph + 1);
    if ((void *)(tcph + 1) > data_end) {
      return XDP_DROP;
    }
    dst_port = tcph->dest;
  } else if (iph->protocol == IPPROTO_UDP) {
    struct udphdr *udph = (void *)(iph + 1);
    if ((void *)(udph + 1) > data_end) {
      return XDP_DROP;
    }
    dst_port = udph->dest;
  } else {
    // Drop ICMP and other protocols
    return XDP_DROP;
  }

  // Allow traffic to controller
  if (dst_port == CONTROLLER_PORT && iph->daddr == CONTROLLER_IP) {
    return XDP_PASS;
  }

  // Check if session is authorized
  struct session_key key = {0};
  key.src_ip = iph->saddr;
  key.dest_ip = iph->daddr;
  key.dest_port = dst_port;

  struct session_val *val = bpf_map_lookup_elem(&session, &key);
  if (val) {
    // Update activity timestamp (with lazy update to reduce overhead)
    u64 now = bpf_ktime_get_ns();
    if (now - val->last_seen_ns >= LAZY_UPDATE_TIMEOUT) {
      val->last_seen_ns = now;
    }
    return XDP_PASS;
  }

  // Default: drop unauthorized traffic
  return XDP_DROP;
}
