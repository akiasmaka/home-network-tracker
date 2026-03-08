// clang-format off
#include <arpa/inet.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h>
// clang-format on

typedef struct connection_stats {
    __u64 packets;
    __u64 bytes;
} connection_stats;

enum direction_type {
    DIR_UNKNOWN = 0,
    DIR_INGRESS = 1,
    DIR_EGRESS = 2,
};

struct ipv4_key {
    unsigned int saddr;
    unsigned int daddr;
    unsigned int ifindex;
    __u64 cgroup_id;
    unsigned char proto;
    unsigned char direction;
    unsigned char pad[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct ipv4_key);
    __type(value, connection_stats);
} ipv4_connection_tracker SEC(".maps");

struct ipv6_key {
    struct in6_addr saddr;
    struct in6_addr daddr;
    unsigned int ifindex;
    __u64 cgroup_id;
    unsigned char proto;
    unsigned char direction;
    unsigned char pad[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, struct ipv6_key);
    __type(value, connection_stats);
} ipv6_connection_tracker SEC(".maps");

static __always_inline int is_ipv6_loopback(const struct in6_addr* addr);

static __always_inline int count_cgroup_packet(struct __sk_buff* skb, __u8 direction) {
    __u16 proto = bpf_ntohs(skb->protocol);

    if (proto == ETH_P_IP) {
        struct iphdr iph;
        if (bpf_skb_load_bytes(skb, 0, &iph, sizeof(iph)) < 0) {
            return 1;
        }

        __u32 saddr = bpf_ntohl(iph.saddr);
        __u32 daddr = bpf_ntohl(iph.daddr);
        if ((saddr & 0xff000000) == 0x7f000000 || (daddr & 0xff000000) == 0x7f000000) {
            return 1;
        }

        unsigned int ip_header_len = iph.ihl * 4;
        if (ip_header_len < sizeof(iph)) {
            return 1;
        }
        __u16 l3_len = bpf_ntohs(iph.tot_len);
        if (l3_len < ip_header_len) {
            return 1;
        }

        unsigned char l4_proto = iph.protocol;
        if (l4_proto != IPPROTO_TCP && l4_proto != IPPROTO_UDP) {
            return 1;
        }

        struct ipv4_key new_connection = {
            iph.saddr,
            iph.daddr,
            skb->ifindex,
            bpf_get_current_cgroup_id(),
            l4_proto,
            direction,
            {0, 0},
        };
        struct connection_stats* stats;

        stats = bpf_map_lookup_elem(&ipv4_connection_tracker, &new_connection);
        if (stats == NULL) {
            __u64 l2_len = (__u64)l3_len + ETH_HLEN;
            struct connection_stats new_stats = {1, l2_len};

            bpf_map_update_elem(&ipv4_connection_tracker, &new_connection, &new_stats, BPF_NOEXIST);
        } else {
            __u64 l2_len = (__u64)l3_len + ETH_HLEN;
            (*stats).bytes += l2_len;
            (*stats).packets++;

            bpf_map_update_elem(&ipv4_connection_tracker, &new_connection, stats, BPF_EXIST);
        }
    } else if (proto == ETH_P_IPV6) {
        struct ipv6hdr ip6h;
        if (bpf_skb_load_bytes(skb, 0, &ip6h, sizeof(ip6h)) < 0) {
            return 1;
        }

        if (is_ipv6_loopback(&ip6h.saddr) || is_ipv6_loopback(&ip6h.daddr)) {
            return 1;
        }

        unsigned char l4_proto = ip6h.nexthdr;
        if (l4_proto != IPPROTO_TCP && l4_proto != IPPROTO_UDP) {
            return 1;
        }

        struct ipv6_key new_connection = {
            ip6h.saddr,
            ip6h.daddr,
            skb->ifindex,
            bpf_get_current_cgroup_id(),
            l4_proto,
            direction,
            {0, 0},
        };
        struct connection_stats* stats;
        __u64 l3_len = (__u64)bpf_ntohs(ip6h.payload_len) + sizeof(ip6h);
        __u64 l2_len = l3_len + ETH_HLEN;
        stats = bpf_map_lookup_elem(&ipv6_connection_tracker, &new_connection);
        if (stats == NULL) {
            struct connection_stats new_stats = {1, l2_len};

            bpf_map_update_elem(&ipv6_connection_tracker, &new_connection, &new_stats, BPF_NOEXIST);
        } else {
            (*stats).bytes += l2_len;
            (*stats).packets++;

            bpf_map_update_elem(&ipv6_connection_tracker, &new_connection, stats, BPF_EXIST);
        }
    }

    return 1;
}

static __always_inline int is_ipv6_loopback(const struct in6_addr* addr) {
    const __u8* bytes = addr->s6_addr;
    if (bytes[0] != 0 || bytes[1] != 0 || bytes[2] != 0 || bytes[3] != 0 ||
        bytes[4] != 0 || bytes[5] != 0 || bytes[6] != 0 || bytes[7] != 0 ||
        bytes[8] != 0 || bytes[9] != 0 || bytes[10] != 0 || bytes[11] != 0 ||
        bytes[12] != 0 || bytes[13] != 0 || bytes[14] != 0) {
        return 0;
    }
    return bytes[15] == 1;
}

SEC("cgroup_skb/ingress")
int cgroup_count_ingress(struct __sk_buff* skb) {
    return count_cgroup_packet(skb, DIR_INGRESS);
}

SEC("cgroup_skb/egress")
int cgroup_count_egress(struct __sk_buff* skb) {
    return count_cgroup_packet(skb, DIR_EGRESS);
}

char _license[] SEC("license") = "GPL";
