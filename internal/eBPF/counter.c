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

 
struct flow_key {
    __u8  family;     // 4: IPv4, 6: IPv6
    __u8  proto;      // IPPROTO_TCP/UDP/ICMP...
    __u16 pad;        // For alignment
    // Changed anonymous union to named structure
    struct {
        __u32 saddr;  // v4 source address
        __u32 daddr;  // v4 destination address
        // IPv6 support preserved but not using anonymous union
        __u64 saddr_hi; // v6 high bits
        __u64 saddr_lo; // v6 low bits
        __u64 daddr_hi; // v6 high bits
        __u64 daddr_lo; // v6 low bits
    } addrs;
    __u16 sport;      // source port
    __u16 dport;      // destination port
};

struct flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 first_ts_ns;
    __u64 last_ts_ns;
};


// LRU Hash: Automatically evicts inactive flows, controls memory usage.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);         // Adjust based on node memory/traffic (128K entries)
    __type(key,   struct flow_key);
    __type(value, struct flow_stats);
} flow_statistics SEC(".maps");

/**
 * @brief Record flow information to the LRU hash map
 * This function extracts the 5-tuple (src/dst IP, src/dst port, protocol) from the packet
 * and updates the flow statistics in the map.
 * 
 * @param ctx XDP context
 * @param iph IP header
 * @param proto Protocol (TCP/UDP)
 * @param sport Source port
 * @param dport Destination port
 * @param pkt_len Packet length in bytes
 * @return 0 on success, negative value on error
 */
static int record_flow(struct iphdr *iph, __u8 proto, __u16 sport, __u16 dport, __u32 pkt_len) {
    struct flow_key key = {};
    struct flow_stats *stats, new_stats = {};
    __u64 ts = bpf_ktime_get_ns();
    
    // Fill in the 5-tuple key
    key.family = 4;  // IPv4
    key.proto = proto;
    key.pad = 0;
    key.addrs.saddr = iph->saddr;
    key.addrs.daddr = iph->daddr;
    key.sport = sport;
    key.dport = dport;
    
    // Look for existing entry
    stats = bpf_map_lookup_elem(&flow_statistics, &key);
    if (stats) {
        // Update existing stats
        stats->packets++;
        stats->bytes += pkt_len;
        stats->last_ts_ns = ts;
        bpf_debug("Updated flow: proto=%u, packets=%llu, bytes=%llu\n", 
                  proto, stats->packets, stats->bytes);
    } else {
        // Create new stats
        new_stats.packets = 1;
        new_stats.bytes = pkt_len;
        new_stats.first_ts_ns = ts;
        new_stats.last_ts_ns = ts;
        bpf_map_update_elem(&flow_statistics, &key, &new_stats, BPF_ANY);
        bpf_debug("New flow: proto=%u\n", proto);
        bpf_debug("New flow SRC: %u.%u.%u\n",
                 (bpf_ntohl(iph->saddr) >> 24) & 0xFF, (bpf_ntohl(iph->saddr) >> 16) & 0xFF,
                 (bpf_ntohl(iph->saddr) >> 8) & 0xFF);
        bpf_debug("New flow SRC: %u:%u\n", 
                 bpf_ntohl(iph->saddr) & 0xFF, bpf_ntohs(sport));
        bpf_debug("New flow DST: %u.%u.%u\n",
                 (bpf_ntohl(iph->daddr) >> 24) & 0xFF, (bpf_ntohl(iph->daddr) >> 16) & 0xFF,
                 (bpf_ntohl(iph->daddr) >> 8) & 0xFF);
        bpf_debug("New flow DST: %u:%u\n", 
                 bpf_ntohl(iph->daddr) & 0xFF, bpf_ntohs(dport));
    }
    
    return 0;
}

static __u32 inner_ipv4_handle(struct xdp_md *ctx, struct iphdr *iph){
    void *p_data_end = (void*)(long)ctx->data_end;
    void *p_data = (void*)(long)ctx->data;

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

    // Process inner protocol (TCP/UDP/ICMP)
    if (iph->protocol == IPPROTO_UDP || iph->protocol == IPPROTO_TCP) {
        void *transport_hdr = (void*)iph + sizeof(*iph);
        __u16 src_port = 0;
        __u16 dst_port = 0;
        
        // Check header boundary
        if (transport_hdr + 4 <= p_data_end) { // Only need first 4 bytes for ports
            // Both TCP and UDP have source port at offset 0 and dest port at offset 2
            src_port = bpf_ntohs(*((__u16 *)transport_hdr));
            dst_port = bpf_ntohs(*((__u16 *)(transport_hdr + 2)));
            __u32 pkt_len = p_data_end - p_data;
            
            // Record flow statistics (works for both UDP and TCP)
            record_flow(iph, iph->protocol, src_port, dst_port, pkt_len);
            
            // Log info about the flow (protocol type is already in the record_flow debug output)
            bpf_debug("Recorded inner %s flow for ports: %u -> %u\n", 
                    (iph->protocol == IPPROTO_UDP) ? "UDP" : "TCP", 
                    src_port, dst_port);
        }
    } else if (iph->protocol == IPPROTO_ICMP) {
        // For ICMP, we don't have ports, but we can use type and code instead
        struct icmphdr {
            __u8 type;
            __u8 code;
            __u16 checksum;
            // Rest of the header varies by type and code
        } __attribute__((packed));
        
        struct icmphdr *icmp = (struct icmphdr *)((void*)iph + sizeof(*iph));
        if ((void*)icmp + sizeof(*icmp) <= p_data_end) {
            __u32 pkt_len = p_data_end - p_data;
            
            // For ICMP, use type as "source port" and code as "destination port"
            // This is just for storage in the flow_key structure
            __u16 type = icmp->type;
            __u16 code = icmp->code;
            
            record_flow(iph, IPPROTO_ICMP, type, code, pkt_len);
            bpf_debug("Recorded inner ICMP flow: type=%u, code=%u\n", type, code);
        }
    } 

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

    __u32 dest_port = bpf_ntohs(udph->dest);
    
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
            bpf_debug("TCP packet\n");
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
