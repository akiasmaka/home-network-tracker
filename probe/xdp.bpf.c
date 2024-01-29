// clang-format off
#include <arpa/inet.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/types.h>
// clang-format on

typedef struct connection_stats {
    __u64 packets;
    __u64 bytes;
} connection_stats;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct connection);
    __type(value, connection_stats);
} connection_tracker SEC(".maps");

struct connection {
    unsigned int saddr;
    unsigned int daddr;
};

SEC("xdp")
int xdp_count_type(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    uint64_t eth_offset = sizeof(*eth);

    if (data + eth_offset > data_end) {
        return XDP_DROP;
    }

    //  Packet data from: https://stackoverflow.com/questions/58255831/xdp-program-ipheader-data-nh-off-confusion
    //  | Ethernet     | IPv4               | IPv4 data (e.g. L4, data)       |
    //  +--------------+--------------------+------ ... ----------------------+
    //  ^              ^                    ^                                 ^
    //  data           data + eth_offset    |                                 data_end
    //                 iph                  |
    //                 &iph[0]              &iph[1]
    struct iphdr *iph = data + eth_offset;
    if ((void *)&iph[1] > data_end) {
        return XDP_ABORTED;
    }

    uint16_t h_proto = eth->h_proto;
    if (h_proto == htons(ETH_P_IP)) {
        struct connection new_connection = {iph->saddr, iph->daddr};
        struct connection_stats *stats;

        stats = bpf_map_lookup_elem(&connection_tracker, &new_connection);
        if (stats == NULL) {
            struct connection_stats new_stats = {0, 0};

            bpf_printk("Got packet to a new connection with source %pI4 and destination %pI4",
                       &iph->saddr,
                       &iph->daddr);

            bpf_map_update_elem(&connection_tracker, &new_connection, &new_stats, BPF_NOEXIST);
        } else {
            (*stats).bytes += data_end - data;
            (*stats).packets++;

            bpf_printk("Got packet to existing connection with source %pI4 and destination %pI4 this is packet number: %lu with a total %lu of bytes transferred",
                       &iph->saddr,
                       &iph->daddr,
                       (*stats).packets,
                       (*stats).bytes);

            bpf_map_update_elem(&connection_tracker, &new_connection, stats, BPF_EXIST);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
