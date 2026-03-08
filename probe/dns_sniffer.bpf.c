// clang-format off
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
// clang-format on

#define DNS_PORT 53

static __always_inline int skb_read_bytes(const struct __sk_buff* skb, int offset,
                                          void* dst, int len) {
    if (offset < 0)
        return -1;

    __u32 skb_len = skb->len;
    if ((__u32)offset + (__u32)len > skb_len)
        return -1;

    if (bpf_skb_load_bytes(skb, offset, dst, len) < 0)
        return -1;

    return 0;
}

static __always_inline int skb_read_u8(const struct __sk_buff* skb, int offset, __u8* out) {
    return skb_read_bytes(skb, offset, out, sizeof(*out));
}

SEC("socket")
int dns_filter(struct __sk_buff* skb) {
    struct ethhdr eth = {};
    int offset = 0;

    if (skb_read_bytes(skb, offset, &eth, sizeof(eth)) < 0)
        return 0;

    offset += sizeof(eth);
    __u16 eth_proto = bpf_ntohs(eth.h_proto);

    int udp_offset = 0;

    if (eth_proto == ETH_P_IP) {
        struct iphdr ip = {};
        if (skb_read_bytes(skb, offset, &ip, sizeof(ip)) < 0)
            return 0;

        if (ip.protocol != IPPROTO_UDP)
            return 0;

        if (ip.ihl < 5)
            return 0;

        udp_offset = offset + (ip.ihl * 4);
    } else if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr ip6 = {};
        if (skb_read_bytes(skb, offset, &ip6, sizeof(ip6)) < 0)
            return 0;

        // Simplified: assume no extension headers
        if (ip6.nexthdr != IPPROTO_UDP)
            return 0;

        udp_offset = offset + sizeof(ip6);
    } else {
        return 0;
    }

    struct udphdr udp = {};
    if (skb_read_bytes(skb, udp_offset, &udp, sizeof(udp)) < 0)
        return 0;

    // Only allow DNS responses (source port 53)
    if (bpf_ntohs(udp.source) != DNS_PORT)
        return 0;

    return skb->len;
}

char _license[] SEC("license") = "GPL";
