#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

char _license[] SEC("license") = "GPL";

SEC("prog")
int xdp_count_type(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    uint64_t offset = sizeof(*eth);
    if (data + offset > data_end){
        return XDP_DROP;
    }

    /**
     * 
     * struct iphdr *iph = data + offset;
     * */ 

    uint16_t h_proto = eth->h_proto;
    if (h_proto == htons(ETH_P_IPV6)){
        return XDP_DROP;
    }

    return XDP_PASS;
}

