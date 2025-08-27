//go:build ignore


#include <linux/bpf.h>  // Any BPF program must include this header
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "protocols/gtpu.h"
#include "utils/debug_tool.h"



char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 16

 
struct conn_tuple {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
};


// Use an LRU hash map to track packet counts for each connection 4-tuple
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, struct conn_tuple);
    __type(value, __u64);  // Use __u64 for large packet counts
} conntrack_map SEC(".maps");

static __u32 inner_ipv4_handle(struct xdp_md *ctx, struct iphdr *iph){
    void *p_data_end = (void*)(long)ctx->data_end;

    if ((void*)iph + sizeof(*iph) > p_data_end) {
        bpf_debug("Invalid inner IPv4 header\n");
        return XDP_ABORTED;
    }
    
    if (iph->version != 4) {
        bpf_debug("Not an inner IPv4 packet\n");
        return XDP_PASS;
    }
    
    __u32 ip_src = bpf_ntohl(iph->saddr);
    __u32 ip_dest = bpf_ntohl(iph->daddr);

    bpf_debug("inner IPv4 src: %u.%u.%u", (ip_src >> 24) & 0xFF, (ip_src >> 16) & 0xFF, (ip_src >> 8) & 0xFF);
    bpf_debug("inner IPv4 src: %u", ip_src & 0xFF);
    bpf_debug("inner IPv4 dst: %u.%u.%u", (ip_dest >> 24) & 0xFF, (ip_dest >> 16) & 0xFF, (ip_dest >> 8) & 0xFF);
    bpf_debug("inner IPv4 dst: %u", ip_dest & 0xFF);

    return XDP_PASS;
}


static __u32 gtp_handle(struct xdp_md* ctx, const void* gtpuh) {
    void *data_end = (void*)(long)ctx->data_end;

    const void *inner = NULL;
    __u16 gtp_msg_len = 0;
    const struct gtpu_fixed *gtp_hdr = NULL;

    /* Locate the inner L3 starting point (automatically handles optional 4B and all ExtHdrs) */
    if (gtpu_locate_inner_l3(gtpuh, data_end, &inner, &gtp_msg_len, &gtp_hdr) < 0) {
        bpf_debug("GTP parse fail\n");
        return XDP_PASS;
    }

    if (inner + 1 > data_end) {
        return XDP_PASS;
    }
    bpf_debug("GTP parse success, msg_len=%u, TEID=%u\n", gtp_msg_len, bpf_ntohl(gtp_hdr->teid));
    bpf_debug("GTP flags: 0x%x, msg_type: %u\n", gtp_hdr->flags, gtp_hdr->msg_type);
    bpf_debug("GTP TEID: %u\n", bpf_ntohl(gtp_hdr->teid));

    inner_ipv4_handle(ctx, (struct iphdr *)inner);

    return XDP_PASS;
}

static __u32 udp_handle(struct xdp_md *ctx, struct udphdr *udph) 
{
    void *p_data_end = (void*)(long)ctx->data_end;
    
    if ((void*)udph + sizeof(*udph) > p_data_end) {
        bpf_debug("Invalid UDP header\n");
        return XDP_ABORTED;
    }

    __u32 dest_port = htons(udph->dest);
    
    switch(dest_port) {
    case GTP_UDP_PORT:
        bpf_debug("GTP packet (dest port=%d)\n", dest_port);
        struct gtpuhdr *gtp_hdr = (void*)udph + sizeof(*udph);
        gtp_handle(ctx, gtp_hdr);
        break;
    default:
        bpf_debug("Unknown UDP packet (dest port=%d)\n", dest_port);
    }

    return XDP_PASS;
}

/**
 * @param ctx The user accessible data for XDP packet hook.
 * @param iph The IP header.
 * @return u32 The XDP action.
 */
static __u32 ipv4_handle(struct xdp_md *ctx, struct iphdr *iph) {
    void* p_data = (void*)(long)ctx->data;
    void *p_data_end = (void*)(long)ctx->data_end;
    
    if ((void*)iph + sizeof(*iph) > p_data_end) {
        bpf_debug("packet length = %d\n", (int)(p_data_end - p_data));
        bpf_debug("IP header size = %d\n", (int)(sizeof(*iph)));
        bpf_debug("The offset between packet_end & ip_header = %d\n", (int)(p_data_end - (void*)iph));
        bpf_debug("Invalid IPv4 header\n");
        return XDP_ABORTED;
    }
    __u32 ip_src = bpf_ntohl(iph->saddr);
    __u32 ip_dest = bpf_ntohl(iph->daddr);

    bpf_debug("IPv4 src: %u.%u.%u", (ip_src >> 24) & 0xFF, (ip_src >> 16) & 0xFF, (ip_src >> 8) & 0xFF);
    bpf_debug("IPv4 src: %u", ip_src & 0xFF);
    bpf_debug("IPv4 dst: %u.%u.%u", (ip_dest >> 24) & 0xFF, (ip_dest >> 16) & 0xFF, (ip_dest >> 8) & 0xFF);
    bpf_debug("IPv4 dst: %u", ip_dest & 0xFF);


    
    switch (iph->protocol) {
        case IPPROTO_UDP:
            bpf_debug("UDP packet\n");
            struct udphdr *udp_hdr = (struct udphdr *)((void*)iph + sizeof(*iph));
            udp_handle(ctx, udp_hdr);
            break;
        case IPPROTO_TCP:
            bpf_debug("TCP packet not supported now\n");
            break;
        default:
            bpf_debug("Unknown IPv4 protocol\n");
            return XDP_PASS;
    }
    return XDP_PASS;
}

struct vlan_hdr {
  __be16 h_vlan_TCI;
  __be16 h_vlan_encapsulated_proto;
};
/** 
 * @param ctx The user accessible data for XDP packet hook
 * @param ethh The Ethernet header.
 * @return XDP action
*/
static __u32 eth_handle(struct xdp_md *ctx, struct ethhdr *ethh) {
    void *p_data_end = (void*)(long)ctx->data_end;
    __u32 dport;
    __u64 offset = sizeof(*ethh);

    // Check Packet Length validity
    if ((void*)ethh + offset > p_data_end) {
        bpf_debug("Invalid Ethernet header\n");
        return XDP_PASS;
    }

    __u16 eth_type = htons(ethh->h_proto);
    bpf_debug("Ethernet type: 0x%x\n", eth_type);

    switch (eth_type) {
    case ETH_P_8021Q:
    case ETH_P_8021AD:
        bpf_debug("IP VLAN -> Change the offset\n");
        struct vlan_hdr *vlan_hdr = (void*)(ethh + 1);
        offset += sizeof(struct vlan_hdr);
        
        // Check Validity of Length
        if ((void*)ethh + offset > p_data_end) {
            bpf_debug("Invalid VLAN header\n");
            return XDP_PASS;
        }
        eth_type = htons(vlan_hdr->h_vlan_encapsulated_proto);

    case ETH_P_IP:
        bpf_debug("IPv4 packet\n");
        struct iphdr *ip_hdr = (struct iphdr *)((void*)ethh + offset);
        return ipv4_handle(ctx, ip_hdr);
        break;
    case ETH_P_IPV6:
        bpf_debug("IPv6 packet\n");
        break;
    default:
        bpf_debug("Unknown Ethernet type\n");
        return XDP_PASS;
    }

    return XDP_PASS;
}

SEC("xdp_entry_point")
int xdp_program_entrypoint(struct xdp_md *ctx) {
    bpf_debug("xdp_program_entrypoint called\n");
    void *data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;

    // Start to handle the ethernet header
    return eth_handle(ctx, eth);

done:
    return XDP_PASS;
}
