#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_drop_prog(struct xdp_md *ctx) {
  (void)ctx;
  // Instructs the kernel to drop the packet immediately
  return XDP_DROP;
}
