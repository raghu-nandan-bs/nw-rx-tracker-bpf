
//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

struct flow_data {
    __u64 rx_packets;
    __u64 rx_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH); 
    __type(key, __u32 /* IPv4 ADDR */);
    __type(value, struct flow_data);
    __uint(max_entries, 1024);
} flow_trackr SEC(".maps"); 

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH); 
    __type(key, __uint128_t /* IPv6 ADDR */);
    __type(value, struct flow_data);
    __uint(max_entries, 1024);
} flow_trackr_ipv6 SEC(".maps"); 

__always_inline  __u32 get_ipv4_addr(void* data_begin, void*data_end ) {
    struct ethhdr *eth = data_begin;
    __u64 eth_offset = sizeof(*eth);

    if (data_begin + eth_offset > data_end) {
        bpf_printk("Ethernet header not fully captured\n");
        return 0;
    }

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {

        struct iphdr *iph = data_begin + eth_offset;
        __u64 iph_offset = sizeof(*iph);

        if (data_begin + eth_offset + iph_offset > data_end) {
            bpf_printk("IP header not fully captured\n");
            return 0;
        }

        return iph->saddr;
    }

    return 0;
}

 __always_inline __uint128_t  get_ipv6_addr(void* data_begin, void*data_end ) {
    struct ethhdr *eth = data_begin;
    __u64 eth_offset = sizeof(*eth);

    if (data_begin + eth_offset > data_end) {
        bpf_printk("Ethernet header not fully captured\n");
        return 0;
    }

    if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = data_begin + eth_offset;
        __u64 ip6h_offset = sizeof(*ip6h);

        if (data_begin + eth_offset + ip6h_offset > data_end) {
            bpf_printk("IPv6 header not fully captured\n");
            return 0;
        }

        return (__uint128_t)(ip6h->saddr.s6_addr);
    } 
    return 0;
}


void __always_inline capture_ipv4_pkt_metrics(__u32 saddr_ipv4, __u64 pkt_size) {
    struct flow_data *data = bpf_map_lookup_elem(&flow_trackr, &saddr_ipv4);
    if (data) {
        data->rx_packets++;
        data->rx_bytes += pkt_size;
    } else {
        struct flow_data new_data = {
            .rx_packets = 1,
            .rx_bytes = pkt_size
        };
        bpf_map_update_elem(&flow_trackr, &saddr_ipv4, &new_data, BPF_ANY);
    }

}

void __always_inline capture_ipv6_pkt_metrics(__uint128_t saddr_ipv6, __u64 pkt_size) {
    struct flow_data *data = bpf_map_lookup_elem(&flow_trackr_ipv6, &saddr_ipv6);
    if (data) {
        data->rx_packets++;
        data->rx_bytes += pkt_size;
    } else {
        struct flow_data new_data = {
            .rx_packets = 1,
            .rx_bytes = pkt_size
        };
        bpf_map_update_elem(&flow_trackr_ipv6, &saddr_ipv6, &new_data, BPF_ANY);
    }

}

SEC("xdp") 
int msr_pkts(struct xdp_md *ctx) {

    struct ethhdr *eth = (void*)ctx->data;
         __u64 eth_offset = sizeof(*eth);

    if ((void*)ctx->data + eth_offset > (void*)ctx->data_end) {
        bpf_printk("Ethernet header not fully captured\n");
        return 0;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP) && eth->h_proto != bpf_htons(ETH_P_IPV6)) {
        bpf_printk("Not an IPv4 or IPv6 packet\n");
        return XDP_PASS;
    }

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        __u32 saddr_ipv4 = get_ipv4_addr((void *)ctx->data, (void *)ctx->data_end);
        capture_ipv4_pkt_metrics(saddr_ipv4, ctx->data_end - ctx->data);
        return XDP_PASS;
    }

    if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        bpf_printk("IPv6 packet\n");
        __uint128_t saddr_ipv6 = get_ipv6_addr((void *)ctx->data, (void *)ctx->data_end);
        capture_ipv6_pkt_metrics(saddr_ipv6, ctx->data_end - ctx->data);
        return XDP_PASS;
    }    

    return XDP_PASS; 
}

char __license[] SEC("license") = "Dual MIT/GPL";