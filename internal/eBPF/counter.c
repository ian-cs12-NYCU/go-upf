//go:build ignore


#include <linux/bpf.h>  // Any BPF program must include this header
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>  // TC classifier support for traffic control
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "protocols/gtpu.h"
#include "utils/debug_tool.h"



char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 16

// Direction constants for flow processing
#define DIRECTION_UL 1  // Uplink - need deep parsing (GTP tunneling)
#define DIRECTION_DL 2  // Downlink - shallow parsing (outer IP only)

// Global variable to track current processing direction
static __u8 current_direction = 0;

struct pkt_rec {
    __u64 ts_ns;        // capture time (monotonic)
    __u32 len;          // packet length
    __u8  l4;           // L4 proto (e.g., IPPROTO_TCP/UDP)
    __u8  dir;          // 0=unknown, 1=ingress, 2=egress (or UL/DL)
    __u8  tcp_flags;    // for TCP only: SYN/ACK/FIN/RST bits
    __u8  dscp_ecn;     // IPv4 TOS or IPv6 traffic class snapshot
};
 
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

// ---- LPM Trie for UL source IP tracking ----
struct ip_key {
    __u32 prefixlen;    // Prefix length (32 for exact match)
    __u32 addr;         // IPv4 address in network byte order
};

struct ip_info {
    __u64 first_seen_ts;    // First time this IP was seen
    __u64 last_seen_ts;     // Last time this IP was seen
    __u64 packet_count;     // Number of packets from this IP
    __u64 byte_count;       // Number of bytes from this IP
};

// LRU Hash: Automatically evicts inactive flows, controls memory usage.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);         // Adjust based on node memory/traffic (128K entries)
    __type(key,   struct flow_key);
    __type(value, struct flow_stats);
} flow_statistics SEC(".maps");

// ---- Added: 16 recent packet ring for each flow ----
#define RECENT_PKT_RING_SIZE 16
#define RECENT_PKT_RING_MASK (RECENT_PKT_RING_SIZE - 1)

struct pkt_ring {
    // TODO: Remove spin lock to avoid requiring BTF support
    // struct bpf_spin_lock lock;
    __u32 head;                             // Incrementally increasing write count
    __u32 count;                            // Number of valid entries filled (<=16)
    struct pkt_rec recs[RECENT_PKT_RING_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);            // Same level as flow_statistics
    __type(key,   struct flow_key);
    __type(value, struct pkt_ring);
} flow_recent_pkts SEC(".maps");

// ---- LPM Trie for tracking UL source IPs ----
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);             // 64K entries for source IPs
    __uint(map_flags, BPF_F_NO_PREALLOC);   // Dynamic allocation
    __type(key, struct ip_key);
    __type(value, struct ip_info);
} ul_source_ips SEC(".maps");

/**
 * @brief Check if an IP address exists in UL source IPs map
 * This function checks if a given IP was previously seen as a UL source
 * 
 * @param ip_addr IP address in network byte order to check
 * @return 1 if IP exists in UL sources, 0 otherwise
 */
static __always_inline int is_ul_source_ip(__u32 ip_addr) {
    struct ip_key key = {};
    struct ip_info *info;
    
    // Set up the key for exact IP match
    key.prefixlen = 32;  // Exact match for IPv4
    key.addr = ip_addr;  // IP in network byte order
    
    // Look for existing entry
    info = bpf_map_lookup_elem(&ul_source_ips, &key);
    if (info) {
        bpf_debug("Found IP in UL sources: packets=%llu !!!!!!!!!!!!!!!!!!!!\n", info->packet_count);
        return 1;  // IP found in UL sources
    }
    
    return 0;  // IP not found
}

/**
 * @brief Record UL source IP in LPM trie
 * This function tracks source IPs that appear in UL traffic
 * 
 * @param src_ip Source IP address in network byte order
 * @param pkt_len Packet length for statistics
 * @return 0 on success, negative value on error
 */
static __always_inline int record_ul_source_ip(struct iphdr *iph, __u32 pkt_len) {
    struct ip_key key = {};
    struct ip_info *info, new_info = {};
    __u64 ts = bpf_ktime_get_ns();
    
    // Set up the key for exact IP match
    key.prefixlen = 32;  // Exact match for IPv4
    key.addr = iph->saddr;  // Already in network byte order
    
    // Look for existing entry
    info = bpf_map_lookup_elem(&ul_source_ips, &key);
    if (info) {
        // Update existing entry
        info->last_seen_ts = ts;
        info->packet_count++;
        info->byte_count += pkt_len;
        bpf_debug("UL(XDP): Updated UL source IP: packets=%llu, bytes=%llu\n", 
                  info->packet_count, info->byte_count);
    } else {
        // Create new entry
        new_info.first_seen_ts = ts;
        new_info.last_seen_ts = ts;
        new_info.packet_count = 1;
        new_info.byte_count = pkt_len;
        
        int ret = bpf_map_update_elem(&ul_source_ips, &key, &new_info, BPF_ANY);
        if (ret == 0) {
            __u32 ip_host = bpf_ntohl(iph->saddr);
            bpf_debug("UL(XDP): New UL source IP recorded: %u.%u.%u", 
                     (ip_host >> 24) & 0xFF, (ip_host >> 16) & 0xFF, (ip_host >> 8) & 0xFF);
            bpf_debug("UL(XDP): New UL source IP recorded: %u\n", ip_host & 0xFF);
        } else {
            bpf_debug("UL(XDP): Failed to add UL source IP: ret=%d\n", ret);
        }
    }
    
    return 0;
}

/**
 * @brief Push a packet record into the ring buffer for a specific flow
 * 
 * @param key Flow key identifying the specific flow
 * @param pkt_rec Packet record to be added to the ring buffer
 * @return 0 on success, negative value on error
 */
static __always_inline int ring_push(struct flow_key *key, struct pkt_rec *rec) {
    struct pkt_ring *ring;
    struct pkt_ring new_ring = {};
    
    // Initialize new ring values
    new_ring.head = 0;
    new_ring.count = 0;
    
    // Try to look up existing ring
    ring = bpf_map_lookup_elem(&flow_recent_pkts, key);
    if (ring) {
        // TODO: No longer need lock operations
        // bpf_spin_lock(&ring->lock);
        
        // Calculate the position to write the new record
        __u32 pos = ring->head & RECENT_PKT_RING_MASK;
        
        // Copy the record into the ring
        ring->recs[pos] = *rec;
        
        // Increment head for next write
        ring->head++;
        
        // Update count (cap at RECENT_PKT_RING_SIZE)
        if (ring->count < RECENT_PKT_RING_SIZE) {
            ring->count++;
        }
        
        // TODO: No longer need unlock operations
        // bpf_spin_unlock(&ring->lock);
        
        bpf_debug("UL(XDP): Updated packet ring: pos=%u, count=%u\n", pos, ring->count);
    } else {
        // Create a new ring with the first packet
        new_ring.head = 1;  // First entry at position 0
        new_ring.count = 1;
        new_ring.recs[0] = *rec;  // Copy the record into the first position
        
        // Add the new ring to the map
        bpf_map_update_elem(&flow_recent_pkts, key, &new_ring, BPF_ANY);
        bpf_debug("UL(XDP): Created new packet ring for flow\n");
    }
    
    return 0;
}

/**
 * @brief Record flow information to the LRU hash map
 * This function extracts the 5-tuple (src/dst IP, src/dst port, protocol) from the packet
 * and updates the flow statistics in the map.
 * 
 * @param iph IP header
 * @param proto Protocol (TCP/UDP)
 * @param sport Source port
 * @param dport Destination port
 * @param pkt_len Packet length in bytes
 * @return 0 on success, negative value on error
 */
static __always_inline int record_flow(struct iphdr *iph, __u8 proto, __u16 sport, __u16 dport, __u32 pkt_len) {
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
        bpf_debug("UL(XDP): Updated flow: proto=%u, packets=%llu, bytes=%llu\n", 
                  proto, stats->packets, stats->bytes);
    } else {
        // Create new stats
        new_stats.packets = 1;
        new_stats.bytes = pkt_len;
        new_stats.first_ts_ns = ts;
        new_stats.last_ts_ns = ts;
        bpf_map_update_elem(&flow_statistics, &key, &new_stats, BPF_ANY);
        bpf_debug("UL(XDP): New flow: proto=%u\n", proto);
        bpf_debug("UL(XDP): New flow SRC: %u.%u.%u\n",
                 (bpf_ntohl(iph->saddr) >> 24) & 0xFF, (bpf_ntohl(iph->saddr) >> 16) & 0xFF,
                 (bpf_ntohl(iph->saddr) >> 8) & 0xFF);
        bpf_debug("UL(XDP): New flow SRC: %u:%u\n", 
                 bpf_ntohl(iph->saddr) & 0xFF, bpf_ntohs(sport));
        bpf_debug("UL(XDP): New flow DST: %u.%u.%u\n",
                 (bpf_ntohl(iph->daddr) >> 24) & 0xFF, (bpf_ntohl(iph->daddr) >> 16) & 0xFF,
                 (bpf_ntohl(iph->daddr) >> 8) & 0xFF);
        bpf_debug("UL(XDP): New flow DST: %u:%u\n", 
                 bpf_ntohl(iph->daddr) & 0xFF, bpf_ntohs(dport));
    }
    
    // Create a packet record for the ring buffer using global direction
    struct pkt_rec pkt_record = {};
    pkt_record.ts_ns = ts;
    pkt_record.len = pkt_len;
    pkt_record.l4 = proto;
    pkt_record.dir = current_direction;  // Use global direction
    pkt_record.tcp_flags = 0;
    pkt_record.dscp_ecn = (iph->tos & 0xFF);
    
    // Push the packet record into the ring buffer for this flow
    bpf_debug("UL(XDP): Recording flow packet to ring buffer\n");
    ring_push(&key, &pkt_record);
    
    return 0;
}

static __always_inline __u32 inner_ipv4_handle(struct xdp_md *ctx, struct iphdr *iph){
    void *p_data_end = (void*)(long)ctx->data_end;
    void *p_data = (void*)(long)ctx->data;

    if ((void*)iph + sizeof(*iph) > p_data_end) {
        bpf_debug("UL(XDP): Invalid inner IPv4 header\n");
        return XDP_ABORTED;
    }
    
    if (iph->version != 4) {
        bpf_debug("UL(XDP): Not an inner IPv4 packet\n");
        return XDP_PASS;
    }
    
    __u32 ip_src = bpf_ntohl(iph->saddr);
    __u32 ip_dest = bpf_ntohl(iph->daddr);

    bpf_debug("UL(XDP): inner IPv4 src: %u.%u.%u", (ip_src >> 24) & 0xFF, (ip_src >> 16) & 0xFF, (ip_src >> 8) & 0xFF);
    bpf_debug("UL(XDP): inner IPv4 src: %u", ip_src & 0xFF);
    bpf_debug("UL(XDP): inner IPv4 dst: %u.%u.%u", (ip_dest >> 24) & 0xFF, (ip_dest >> 16) & 0xFF, (ip_dest >> 8) & 0xFF);
    bpf_debug("UL(XDP): inner IPv4 dst: %u", ip_dest & 0xFF);

    // Record UL source IP in LPM trie (this is inner IP, so it's the real user IP)
    __u32 pkt_len = p_data_end - p_data;
    record_ul_source_ip(iph, pkt_len);

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
            
            // Record flow statistics (works for both UDP and TCP) - inner flow is always UL
            record_flow(iph, iph->protocol, src_port, dst_port, pkt_len);
            
            // Log info about the flow (protocol type is already in the record_flow debug output)
            bpf_debug("UL(XDP): Recorded inner %s flow for ports: %u -> %u\n", 
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
            bpf_debug("UL(XDP): Recorded inner ICMP flow: type=%u, code=%u\n", type, code);
        }
    } 

    return XDP_PASS;
}

static __always_inline __u32 gtp_handle(struct xdp_md* ctx, const void* gtpuh) {
    void *data_end = (void*)(long)ctx->data_end;

    const void *inner = NULL;
    __u16 gtp_msg_len = 0;
    const struct gtpu_fixed *gtp_hdr = NULL;

    /* Locate the inner L3 starting point (automatically handles optional 4B and all ExtHdrs) */
    if (gtpu_locate_inner_l3(gtpuh, data_end, &inner, &gtp_msg_len, &gtp_hdr) < 0) {
        bpf_debug("UL(XDP): GTP parse fail\n");
        return XDP_PASS;
    }

    if (inner + 1 > data_end) {
        return XDP_PASS;
    }
    bpf_debug("UL(XDP): GTP parse success, msg_len=%u, TEID=%u\n", gtp_msg_len, bpf_ntohl(gtp_hdr->teid));
    bpf_debug("UL(XDP): GTP flags: 0x%x, msg_type: %u\n", gtp_hdr->flags, gtp_hdr->msg_type);
    bpf_debug("UL(XDP): GTP TEID: %u\n", bpf_ntohl(gtp_hdr->teid));

    inner_ipv4_handle(ctx, (struct iphdr *)inner);

    return XDP_PASS;
}

static __always_inline __u32 udp_handle(struct xdp_md *ctx, struct udphdr *udph, __u8 direction) 
{
    void *p_data_end = (void*)(long)ctx->data_end;
    
    if ((void*)udph + sizeof(*udph) > p_data_end) {
        bpf_debug("UL(XDP): Invalid UDP header\n");
        return XDP_ABORTED;
    }

    __u32 dest_port = bpf_ntohs(udph->dest);
    
    // Only parse GTP for UL traffic
    if (direction == DIRECTION_UL && dest_port == GTP_UDP_PORT) {
        bpf_debug("UL(XDP): GTP packet (dest port=%d) - UL traffic\n", dest_port);
        struct gtpuhdr *gtp_hdr = (void*)udph + sizeof(*udph);
        gtp_handle(ctx, gtp_hdr);
    } else {
        bpf_debug("UL(XDP): Non-GTP UDP packet (dest port=%d) or DL traffic\n", dest_port);
    }

    return XDP_PASS;
}

/**
 * @param ctx The user accessible data for XDP packet hook.
 * @param iph The IP header.
 * @param direction Direction (UL/DL)
 * @return u32 The XDP action.
 */
static __always_inline __u32 ipv4_handle(struct xdp_md *ctx, struct iphdr *iph, __u8 direction) {
    void* p_data = (void*)(long)ctx->data;
    void *p_data_end = (void*)(long)ctx->data_end;
    
    if ((void*)iph + sizeof(*iph) > p_data_end) {
        bpf_debug("UL(XDP): packet length = %d\n", (int)(p_data_end - p_data));
        bpf_debug("UL(XDP): IP header size = %d\n", (int)(sizeof(*iph)));
        bpf_debug("UL(XDP): The offset between packet_end & ip_header = %d\n", (int)(p_data_end - (void*)iph));
        bpf_debug("UL(XDP): Invalid IPv4 header\n");
        return XDP_ABORTED;
    }
    __u32 ip_src = bpf_ntohl(iph->saddr);
    __u32 ip_dest = bpf_ntohl(iph->daddr);

    bpf_debug("UL(XDP): IPv4 src: %u.%u.%u", (ip_src >> 24) & 0xFF, (ip_src >> 16) & 0xFF, (ip_src >> 8) & 0xFF);
    bpf_debug("UL(XDP): IPv4 src: %u", ip_src & 0xFF);
    bpf_debug("UL(XDP): IPv4 dst: %u.%u.%u", (ip_dest >> 24) & 0xFF, (ip_dest >> 16) & 0xFF, (ip_dest >> 8) & 0xFF);
    bpf_debug("UL(XDP): IPv4 dst: %u", ip_dest & 0xFF);

    // For DL traffic, only record flow if dest IP was previously a UL source
    if (direction == DIRECTION_DL) {
        __u32 pkt_len = p_data_end - p_data;
        bpf_debug("DL(TC): DL traffic: checking if dest IP was UL source\n");
        
        // Check if destination IP exists in UL source IPs
        if (is_ul_source_ip(iph->daddr)) {
            bpf_debug("DL(TC): DL traffic: dest IP found in UL sources, recording outer flow\n");
            // For DL outer flow, use port 0 since we don't parse L4 headers
            record_flow(iph, iph->protocol, 0, 0, pkt_len);
        } else {
            bpf_debug("DL(TC): DL traffic: dest IP (%u.%u.%u", 
                      (bpf_ntohl(iph->daddr) >> 24) & 0xFF, (bpf_ntohl(iph->daddr) >> 16) & 0xFF, (bpf_ntohl(iph->daddr) >> 8) & 0xFF);
            bpf_debug("DL(TC): DL traffic: dest IP %u) not in UL sources, skipping flow record\n", 
                      bpf_ntohl(iph->daddr) & 0xFF);
        }
        return XDP_PASS;
    }

    // For UL traffic, continue deep parsing
    switch (iph->protocol) {
        case IPPROTO_UDP:
            bpf_debug("UL(XDP): UDP packet - UL traffic, continue parsing\n");
            struct udphdr *udp_hdr = (struct udphdr *)((void*)iph + sizeof(*iph));
            udp_handle(ctx, udp_hdr, direction);
            break;
        case IPPROTO_TCP:
            bpf_debug("UL(XDP): TCP packet - UL traffic\n");
            break;
        default:
            bpf_debug("UL(XDP): Unknown IPv4 protocol - UL traffic\n");
            return XDP_PASS;
    }
    return XDP_PASS;
}

struct vlan_hdr {
  __be16 h_vlan_TCI;
  __be16 h_vlan_encapsulated_proto;
};

/**
 * @brief Handle IPv4 packets for TC egress (DL traffic)
 * This function is specifically designed for TC egress processing with __sk_buff
 * 
 * @param skb Socket buffer containing packet data
 * @param iph IPv4 header
 * @return TC action code (TC_ACT_OK to continue, TC_ACT_SHOT to drop)
 */
static __always_inline __u32 tc_ipv4_handle(struct __sk_buff *skb, struct iphdr *iph) {
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;
    
    if ((void*)iph + sizeof(*iph) > data_end) {
        bpf_debug("DL(TC): Invalid IPv4 header\n");
        return TC_ACT_OK;
    }
    
    __u32 ip_src = bpf_ntohl(iph->saddr);
    __u32 ip_dest = bpf_ntohl(iph->daddr);

    bpf_debug("DL(TC): IPv4 src: %u.%u.%u", (ip_src >> 24) & 0xFF, (ip_src >> 16) & 0xFF, (ip_src >> 8) & 0xFF);
    bpf_debug("DL(TC): IPv4 src: %u", ip_src & 0xFF);
    bpf_debug("DL(TC): IPv4 dst: %u.%u.%u", (ip_dest >> 24) & 0xFF, (ip_dest >> 16) & 0xFF, (ip_dest >> 8) & 0xFF);
    bpf_debug("DL(TC): IPv4 dst: %u", ip_dest & 0xFF);

    // For DL traffic, only record flow if dest IP was previously a UL source
    __u32 pkt_len = data_end - data;
    bpf_debug("DL(TC): checking if dest IP was UL source\n");
    
    // Check if destination IP exists in UL source IPs
    if (is_ul_source_ip(iph->daddr)) {
        bpf_debug("DL(TC): dest IP found in UL sources, recording outer flow\n");
        // For DL outer flow, use port 0 since we don't parse L4 headers in DL
        record_flow(iph, iph->protocol, 0, 0, pkt_len);
    } else {
        bpf_debug("DL(TC): dest IP (%u.%u.%u", 
                  (bpf_ntohl(iph->daddr) >> 24) & 0xFF, (bpf_ntohl(iph->daddr) >> 16) & 0xFF, (bpf_ntohl(iph->daddr) >> 8) & 0xFF);
        bpf_debug("DL(TC): dest IP %u) not in UL sources, skipping flow record\n", 
                  bpf_ntohl(iph->daddr) & 0xFF);
    }
    
    return TC_ACT_OK;
}


/** 
 * @param ctx The user accessible data for XDP packet hook
 * @param ethh The Ethernet header.
 * @param direction Direction (UL/DL)
 * @return XDP action
*/
static __always_inline __u32 eth_handle(struct xdp_md *ctx, struct ethhdr *ethh, __u8 direction) {
    void *p_data_end = (void*)(long)ctx->data_end;
    __u32 dport;
    __u64 offset = sizeof(*ethh);

    // Check Packet Length validity
    if ((void*)ethh + offset > p_data_end) {
        bpf_debug("UL(XDP): Invalid Ethernet header\n");
        return XDP_PASS;
    }

    __u16 eth_type = htons(ethh->h_proto);
    bpf_debug("UL(XDP): Ethernet type: 0x%x\n", eth_type);

    switch (eth_type) {
    case ETH_P_8021Q:
    case ETH_P_8021AD:
        bpf_debug("UL(XDP): IP VLAN -> Change the offset\n");
        struct vlan_hdr *vlan_hdr = (void*)(ethh + 1);
        offset += sizeof(struct vlan_hdr);
        
        // Check Validity of Length
        if ((void*)ethh + offset > p_data_end) {
            bpf_debug("UL(XDP): Invalid VLAN header\n");
            return XDP_PASS;
        }
        eth_type = htons(vlan_hdr->h_vlan_encapsulated_proto);

    case ETH_P_IP:
        bpf_debug("UL(XDP): IPv4 packet\n");
        struct iphdr *ip_hdr = (struct iphdr *)((void*)ethh + offset);
        return ipv4_handle(ctx, ip_hdr, direction);
        break;
    case ETH_P_IPV6:
        bpf_debug("UL(XDP): IPv6 packet\n");
        break;
    default:
        bpf_debug("UL(XDP): Unknown Ethernet type\n");
        return XDP_PASS;
    }

    return XDP_PASS;
}

SEC("xdp/ul")
int ul_xdp_program_entrypoint(struct xdp_md *ctx) {
    // bpf_debug("ul_xdp_program_entrypoint called - UL traffic\n");
    
    // Set global direction for this packet processing
    current_direction = DIRECTION_UL;
    
    void *data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;

    // Start to handle the ethernet header with UL direction
    return eth_handle(ctx, eth, DIRECTION_UL);

done:
    return XDP_PASS;
}

/**
 * @brief TC egress program for downlink traffic processing
 * This function processes downlink (DL) packets at TC egress point.
 * Uses dedicated TC handling functions optimized for __sk_buff context.
 * 
 * @param skb Socket buffer containing packet data
 * @return TC_ACT_OK to continue packet transmission, TC_ACT_SHOT to drop
 */
SEC("tc")
int dl_tc_program_entrypoint(struct __sk_buff *skb) {
    // bpf_debug("dl_tc_program_entrypoint called - DL traffic\n");
    
    // Set global direction for this packet processing
    current_direction = DIRECTION_DL;
    
    void *data = (void*)(long)skb->data;
    void *data_end = (void*)(long)skb->data_end;
    
    // In TC egress, skb->data points directly to IP header, not Ethernet header
    if (data + sizeof(struct iphdr) > data_end) {
        bpf_debug("DL(TC): Invalid packet length for IP header\n");
        return TC_ACT_OK;
    }
    
    struct iphdr *iph = data;
    
    // Validate IP version
    if (iph->version != 4) {
        bpf_debug("DL(TC): Non-IPv4 packet (version=%d)\n", iph->version);
        return TC_ACT_OK;
    }
    
    bpf_debug("DL(TC): IPv4 packet detected\n");
    
    // Process DL traffic using TC IPv4 handling
    return tc_ipv4_handle(skb, iph);
}