//go:build ignore


#include <linux/bpf.h>  // Any BPF program must include this header
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define bpf_debug(fmt, ...)						\
		({							\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
				     ##__VA_ARGS__);			\
		})



char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 16
#define GTP_PORT 2152
#define GTP_HEADER_LEN 8

struct conn_tuple {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
};

struct gtp_header {
    __u8 flags;
    __u8 message_type;
    __be16 length;
    __be32 teid;
};

// 用一個 LRU hash map 來紀錄每個連線四元組的封包數量
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, struct conn_tuple);
    __type(value, __u64);  // 若封包數量可能很大，用 __u64 比較安全
} conntrack_map SEC(".maps");

/*
Attempt to parse the IPv4 source address from the packet.
Returns 0 if there is no IPv4 header field; otherwise returns non-zero.
*/
static __always_inline int parse_ip_addr(struct xdp_md *ctx, __u32 *ip_src_addr, __u32 *ip_dest_addr) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	// First, parse the ethernet header.
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		const char msg[] = "The ethernet header is incomplete.\n";
		bpf_trace_printk(msg, sizeof(msg));
		return 0;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		// The protocol is not IPv4, so we can't parse an IPv4 source address.
		const char msg[] = "The protocol is not IPv4, so we can't parse an IPv4 source address.\n";
		bpf_trace_printk(msg, sizeof(msg));
		return 0;
	}

	// Then parse the IP header.
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		return 0;
	}

	// Return the source IP address in network byte order.
	*ip_src_addr = (__u32)(ip->saddr);
	*ip_dest_addr = (__u32)(ip->daddr);
	return 1;
}

// Parse GTP header and extract inner IP header
static __always_inline int parse_gtp_tunnel(struct xdp_md *ctx, void **data, void **data_end, struct iphdr **inner_ip) {
    struct udphdr *udp = *data;
    if ((void *)(udp + 1) > *data_end) {
        return 0;
    }

    // Check if the UDP port matches GTP (2152)
    if (udp->source != bpf_htons(GTP_PORT) && udp->dest != bpf_htons(GTP_PORT)) {
        return 0;
    }

    struct gtp_header *gtp = (void *)(udp + 1);
    if ((void *)(gtp + 1) > *data_end) {
        return 0;
    }

    // Check if the GTP message type is T-PDU (0xff)
    if (gtp->message_type != 0xff) {
        return 0;
    }

    // Extract the inner IP header
    *inner_ip = (void *)(gtp + 1);
    if ((void *)(*inner_ip + 1) > *data_end) {
        return 0;
    }

    return 1;
}

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

	// check if the ethernet header is complete
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        const char msg[] = "The ethernet header is incomplete.\n";
        bpf_trace_printk(msg, sizeof(msg));
        return XDP_PASS;
    }

    // Check if the protocol is IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        const char msg[] = "The protocol is not IPv4, so we can't parse an IPv4 source address.\n";
        bpf_trace_printk(msg, sizeof(msg));
        return XDP_PASS;
    }

    struct iphdr *outer_ip = (void *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end) {
        const char msg[] = "The outer IP header is incomplete.\n";
        bpf_trace_printk(msg, sizeof(msg));
        return XDP_PASS;
    }

    // Check if the outer IP protocol is UDP
    if (outer_ip->protocol != IPPROTO_UDP) {
        const char msg[] = "The outer IP protocol is not UDP, so we can't parse the inner IP header.\n";
        bpf_trace_printk(msg, sizeof(msg));
        return XDP_PASS;
    }

    struct iphdr *inner_ip = NULL;
    void *udp = (void *)outer_ip + (outer_ip->ihl * 4);

    // Parse GTP tunnel and extract inner IP
    if (!parse_gtp_tunnel(ctx, &udp, &data_end, &inner_ip)) {
        return XDP_PASS;
    }

    // Parse inner IP and TCP/UDP headers
    __u32 src_ip = inner_ip->saddr;
    __u32 dest_ip = inner_ip->daddr;

    // Directly print source and destination IP addresses using %pI4
    bpf_debug("Inner Src IP: %pI4, Inner Dest IP: %pI4\n", &src_ip, &dest_ip);

    struct conn_tuple key = {0};
    key.src_ip   = src_ip;
    key.dst_ip   = dest_ip;
    key.src_port = 0;
    key.dst_port = 0;

    __u64 *pkt_count = bpf_map_lookup_elem(&conntrack_map, &key);
    if (!pkt_count) {
        __u64 init_pkt_count = 1;
        bpf_map_update_elem(&conntrack_map, &key, &init_pkt_count, BPF_ANY);
        bpf_debug("key:(src:%pI4, dst:%pI4) packet count = %d\n", &key.src_ip, &key.dst_ip, init_pkt_count);
    } else {
        __sync_fetch_and_add(pkt_count, 1);
        bpf_debug("key:(src:%pI4, dst:%pI4) packet count = %d\n", &key.src_ip, &key.dst_ip, *pkt_count);
    }

done:
    return XDP_PASS;
}
