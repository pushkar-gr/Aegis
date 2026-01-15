#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "GPL";

#define ETH_P_IP    0x0800
#define ETH_P_ARP   0x0806
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/**
 * @brief Configuration Constants
 *
 * Dynamic configuration of controller ip:port
 */
volatile const __u32 CONTROLLER_IP;   // Big Endian (Network Byte Order)
volatile const __u16 CONTROLLER_PORT; // Little Endian (Host Byte Order)

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
 * 4. Drop everything else.
 *
 * @param ctx Context containing packet data pointers.
 * @return XDP_PASS to accept the packet, XDP_DROP to discard it.
 */
SEC("xdp")
int xdp_drop_prog(struct xdp_md *ctx) {
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
    // Drop non-TCP/UDP IPv4 packets (e.g., ICMP)
    return XDP_DROP;
  }

  // 4. Policy Enforcement
  // Check if traffic is destined for the Controller
  if (dst_port == CONTROLLER_PORT && iph->daddr == CONTROLLER_IP) {
    bpf_printk("Aegis: Accepted packet from Controller");
    return XDP_PASS;
  }

  // DEFAULT DENY: Drop all other traffic
  return XDP_DROP;
}
