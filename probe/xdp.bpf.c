#include <arpa/inet.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_count_type(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;

  uint64_t offset = sizeof(*eth);
  if (data + offset > data_end) {
    return XDP_DROP;
  }

  /**
   * See: https://github.com/akiasmaka/home-network-tracker/issues/8
   * struct iphdr *iph = data + offset;
   * */

  uint16_t h_proto = eth->h_proto;
  if (h_proto == htons(ETH_P_IPV6)) {
    return XDP_DROP;
  }

  return XDP_PASS;
}
