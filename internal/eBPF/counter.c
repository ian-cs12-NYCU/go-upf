//go:build ignore


#include <linux/bpf.h>  // Any BPF program must include this header
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>



char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 16

struct conn_tuple {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
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
		return 0;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		// The protocol is not IPv4, so we can't parse an IPv4 source address.
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

static __always_inline int parse_tcp_port(struct xdp_md *ctx, __be16 *src_port, __be16 *dest_port) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	// First, parse the ethernet header.
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return 0;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		// The protocol is not IPv4, so we can't parse an IPv4 source address.
		return 0;
	}

	// Then parse the IP header.
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		return 0;
	}

	if (ip->protocol != IPPROTO_TCP) {
		// The protocol is not TCP, so we can't parse a TCP port.
		return 0;
	}

	// -------- Then parse the TCP header. ----------------
	struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
	if ((void *)(tcp + 1) > data_end) {
		return 0;
	}

	// Return the source port in network byte order.
	*src_port = (__u16)(tcp->source);
	*dest_port = (__u16)(tcp->dest);
	return 1;
}



SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
    __u32 src_ip, dest_ip;
    __be16 src_port, dest_port;
    struct conn_tuple key = {0};

    if (!parse_ip_addr(ctx, &src_ip, &dest_ip))
        goto done;

    if (!parse_tcp_port(ctx, &src_port, &dest_port))
        goto done;

    key.src_ip   = src_ip;
    key.dst_ip   = dest_ip;
    key.src_port = src_port;
    key.dst_port = dest_port;

    __u64 *pkt_count = bpf_map_lookup_elem(&conntrack_map, &key);
    if (!pkt_count) {
        __u64 init_pkt_count = 1;
        bpf_map_update_elem(&conntrack_map, &key, &init_pkt_count, BPF_ANY);
    } else {
        __sync_fetch_and_add(pkt_count, 1);
    }

	// If not using the following code, the program will be optimized out
	// Degug message will cause performance issue
	if (!pkt_count) {
		const char msg[] = " 'pkt_count' pointer lose\n";
		bpf_trace_printk(msg, sizeof(msg));
		goto done;
	} else {
		const char msg[] = "Hello, packet count = %d\n";
		bpf_trace_printk(msg, sizeof(msg), *pkt_count);
	}

done:
    return XDP_PASS;
}
