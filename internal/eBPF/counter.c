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
#include "include/ebpf_maps.h"



char __license[] SEC("license") = "Dual MIT/GPL";

// Global variable to track current processing direction
static __u8 current_direction = 0;

/**
 * @brief Check if packet should be sampled based on sampling configuration
 * 
 * Uses per-CPU counters for reliable sampling that avoids bias from
 * periodic traffic patterns or timestamp-based sampling issues.
 * 
 * @param proto L4 protocol
 * @return 1 if packet should be sampled, 0 otherwise
 */
static __always_inline int should_sample_packet(__u8 proto) {
    __u32 key = 0;
    struct sampling_config *config = bpf_map_lookup_elem(&sampling_control, &key);
    
    // Default to sample all if no config
    if (!config) {
        return 1;
    }
    
    // Apply sample rate using per-CPU counter for fair sampling
    if (config->sample_rate > 1) {
        __u64 *counter = bpf_map_lookup_elem(&sampling_counter, &key);
        
        if (!counter) {
            // Initialize counter if not found
            __u64 init_val = 1;
            bpf_map_update_elem(&sampling_counter, &key, &init_val, BPF_ANY);
            return 1;  // Sample the first packet
        }
        
        // Increment counter
        __u64 current_count = *counter + 1;
        bpf_map_update_elem(&sampling_counter, &key, &current_count, BPF_ANY);
        
        // Check if this packet should be sampled
        if ((current_count % config->sample_rate) != 0) {
            return 0;  // Skip this packet
        }
    }
    
    return 1;  // Sample this packet
}

/**
 * @brief Send packet event to global perf event array
 * 
 * @param ctx The context (XDP or TC)
 * @param event Packet event to send
 * @return 0 on success, negative on error
 */
static __always_inline int send_packet_event(void *ctx, struct pkt_event *event) {
    __u32 cpu = bpf_get_smp_processor_id();
    __u32 key = 0;
    __u64 *counter;
    
    // Get per-CPU counter for wake-up control
    counter = bpf_map_lookup_elem(&event_counter, &key);
    if (!counter) {
        // Initialize counter if not found
        __u64 init_val = 1;
        bpf_map_update_elem(&event_counter, &key, &init_val, BPF_ANY);
        
        // Send event with wakeup
        return bpf_perf_event_output(ctx, &packet_events, BPF_F_CURRENT_CPU, 
                                   event, sizeof(*event));
    }
    
    // Increment counter
    __u64 current_count = *counter + 1;
    bpf_map_update_elem(&event_counter, &key, &current_count, BPF_ANY);
    
    // Determine if we should wake up userspace
    __u64 flags = BPF_F_CURRENT_CPU;
    if ((current_count % WAKE_UP_INTERVAL) == 0) {
        // Force wakeup every WAKE_UP_INTERVAL events
        flags |= 0;  // No special flags for wakeup
        bpf_debug(DBG_PACKET, "Waking up userspace at event %llu\n", current_count);
    } else {
        // No wakeup for this event (reduce overhead)
        flags |= BPF_F_CURRENT_CPU;
    }
    
    // Send event to perf buffer
    return bpf_perf_event_output(ctx, &packet_events, flags, 
                               event, sizeof(*event));
}

/**
 * @brief Create and send packet event for given flow
 * This function extracts necessary fields and sends them to the global event buffer
 * 
 * @param ctx The context (XDP or TC)
 * @param iph IP header
 * @param proto L4 protocol
 * @param sport Source port
 * @param dport Destination port
 * @param pkt_len Packet length
 * @param tcp_flags TCP flags (0 for non-TCP)
 * @return 0 on success, negative on error
 */
static __always_inline int create_and_send_event(void *ctx, struct iphdr *iph, __u8 proto, 
                                                __u16 sport, __u16 dport, __u32 pkt_len,
                                                __u8 tcp_flags) {
    // Check sampling configuration first
    if (!should_sample_packet(proto)) {
        return 0;  // Skip this packet
    }
    
    struct pkt_event event = {};
    
    // Fill event structure
    event.ts_ns = bpf_ktime_get_ns();
    event.saddr_v4 = iph->saddr;  // Already in network byte order
    event.daddr_v4 = iph->daddr;  // Already in network byte order
    event.ifindex = 0;  // Will be set by caller if needed
    event.sport = sport;
    event.dport = dport;
    event.len = (__u16)pkt_len;
    event.dir = current_direction;
    event.l4 = proto;
    event.tcp_flags = tcp_flags;
    event.dscp_ecn = iph->tos;
    event.ttl_hl = iph->ttl;
    event.l3_frag = (iph->frag_off & bpf_htons(0x3FFF)) ? 1 : 0;  // Check if fragmented
    event.family = 4;  // IPv4
    event.reserved = 0;  // Initialize reserved field
    
    // Send event to global buffer
    int ret = send_packet_event(ctx, &event);
    if (ret < 0) {
        bpf_debug(DBG_PACKET, "Failed to send packet event: %d\n", ret);
        return ret;
    }
    
    bpf_debug(DBG_PACKET, "Sent packet event: proto=%u, len=%u\n", 
              proto, pkt_len);
    return 0;
}

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
        bpf_debug(DBG_PACKET, "Found IP in UL sources: packets=%llu !!!!!!!!!!!!!!!!!!!!\n", info->packet_count);
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
        bpf_debug(DBG_PACKET, "UL(XDP): Updated UL source IP: packets=%llu, bytes=%llu\n", 
                  info->packet_count, info->byte_count);
    } else {
        // Create new entry
        new_info.first_seen_ts = ts;
        new_info.last_seen_ts = ts;
        new_info.packet_count = 1;
        new_info.byte_count = pkt_len;
        
        int ret = bpf_map_update_elem(&ul_source_ips, &key, &new_info, BPF_ANY);
        if (ret == 0) {
            bpf_debug(DBG_PACKET, "UL(XDP): New UL source IP recorded\n");
        } else {
            bpf_debug(DBG_PACKET, "UL(XDP): Failed to add UL source IP: ret=%d\n", ret);
        }
    }
    
    return 0;
}



/**
 * @brief Record flow information and send packet event to global buffer
 * This function extracts the 5-tuple (src/dst IP, src/dst port, protocol) from the packet,
 * updates the flow statistics, and sends an event to the global buffer.
 * 
 * @param ctx The context (XDP or TC)
 * @param iph IP header
 * @param proto Protocol (TCP/UDP)
 * @param sport Source port
 * @param dport Destination port
 * @param pkt_len Packet length in bytes
 * @param tcp_flags TCP flags (0 for non-TCP)
 * @return 0 on success, negative value on error
 */
static __always_inline int record_flow_and_send_event(void *ctx, struct iphdr *iph, __u8 proto, 
                                                    __u16 sport, __u16 dport, __u32 pkt_len,
                                                    __u8 tcp_flags) {
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
        bpf_debug(DBG_PACKET, "Updated flow: proto=%u, packets=%llu, bytes=%llu\n", 
                  proto, stats->packets, stats->bytes);
    } else {
        // Create new stats
        new_stats.packets = 1;
        new_stats.bytes = pkt_len;
        new_stats.first_ts_ns = ts;
        new_stats.last_ts_ns = ts;
        bpf_map_update_elem(&flow_statistics, &key, &new_stats, BPF_ANY);
        bpf_debug(DBG_PACKET, "New flow: proto=%u\n", proto);
    }
    
    // Send packet event to global buffer (instead of per-flow ring buffer)
    int ret = create_and_send_event(ctx, iph, proto, sport, dport, pkt_len, tcp_flags);
    if (ret < 0) {
        bpf_debug(DBG_PACKET, "Failed to send packet event: %d\n", ret);
        // Continue even if event sending fails - don't break flow tracking
    } else {
        bpf_debug(DBG_PACKET, "Sent packet event to global buffer\n");
    }
    
    return 0;
}

// Legacy wrapper function for backward compatibility
static __always_inline int record_flow(void *ctx, struct iphdr *iph, __u8 proto, __u16 sport, __u16 dport, __u32 pkt_len) {
    return record_flow_and_send_event(ctx, iph, proto, sport, dport, pkt_len, 0);
}

static __always_inline __u32 inner_ipv4_handle(struct xdp_md *ctx, struct iphdr *iph){
    void *p_data_end = (void*)(long)ctx->data_end;
    void *p_data = (void*)(long)ctx->data;

    if ((void*)iph + sizeof(*iph) > p_data_end) {
        bpf_debug(DBG_PACKET, "UL(XDP): Invalid inner IPv4 header\n");
        return XDP_ABORTED;
    }
    
    if (iph->version != 4) {
        bpf_debug(DBG_PACKET, "UL(XDP): Not an inner IPv4 packet\n");
        return XDP_PASS;
    }
    
    __u32 ip_src = bpf_ntohl(iph->saddr);
    __u32 ip_dest = bpf_ntohl(iph->daddr);

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
            record_flow(ctx, iph, iph->protocol, src_port, dst_port, pkt_len);
            
            // Log info about the flow (protocol type is already in the record_flow debug output)
            bpf_debug(DBG_PACKET, "UL(XDP): Recorded inner %s flow for ports: %u -> %u\n", 
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
            
            record_flow(ctx, iph, IPPROTO_ICMP, type, code, pkt_len);
            bpf_debug(DBG_PACKET, "UL(XDP): Recorded inner ICMP flow: type=%u, code=%u\n", type, code);
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
        bpf_debug(DBG_PACKET, "UL(XDP): GTP parse fail\n");
        return XDP_PASS;
    }

    if (inner + 1 > data_end) {
        return XDP_PASS;
    }
    bpf_debug(DBG_PACKET, "UL(XDP): GTP parse success, msg_len=%u, TEID=%u\n", gtp_msg_len, bpf_ntohl(gtp_hdr->teid));
    bpf_debug(DBG_PACKET, "UL(XDP): GTP flags: 0x%x, msg_type: %u\n", gtp_hdr->flags, gtp_hdr->msg_type);
    bpf_debug(DBG_PACKET, "UL(XDP): GTP TEID: %u\n", bpf_ntohl(gtp_hdr->teid));

    inner_ipv4_handle(ctx, (struct iphdr *)inner);

    return XDP_PASS;
}

static __always_inline __u32 udp_handle(struct xdp_md *ctx, struct udphdr *udph, __u8 direction) 
{
    void *p_data_end = (void*)(long)ctx->data_end;
    
    if ((void*)udph + sizeof(*udph) > p_data_end) {
        bpf_debug(DBG_PACKET, "UL(XDP): Invalid UDP header\n");
        return XDP_ABORTED;
    }

    __u32 dest_port = bpf_ntohs(udph->dest);
    
    // Only parse GTP for UL traffic
    if (direction == DIRECTION_UL && dest_port == GTP_UDP_PORT) {
        bpf_debug(DBG_PACKET, "UL(XDP): GTP packet (dest port=%d) - UL traffic\n", dest_port);
        struct gtpuhdr *gtp_hdr = (void*)udph + sizeof(*udph);
        gtp_handle(ctx, gtp_hdr);
    } else {
        bpf_debug(DBG_PACKET, "UL(XDP): Non-GTP UDP packet (dest port=%d) or DL traffic\n", dest_port);
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
        bpf_debug(DBG_PACKET, "UL(XDP): packet length = %d\n", (int)(p_data_end - p_data));
        bpf_debug(DBG_PACKET, "UL(XDP): IP header size = %d\n", (int)(sizeof(*iph)));
        bpf_debug(DBG_PACKET, "UL(XDP): The offset between packet_end & ip_header = %d\n", (int)(p_data_end - (void*)iph));
        bpf_debug(DBG_PACKET, "UL(XDP): Invalid IPv4 header\n");
        return XDP_ABORTED;
    }
    __u32 ip_src = bpf_ntohl(iph->saddr);
    __u32 ip_dest = bpf_ntohl(iph->daddr);
    bpf_debug(DBG_PACKET, "UL(XDP): IPv4 src: %u.%u.%u", (ip_src >> 24) & 0xFF, (ip_src >> 16) & 0xFF, (ip_src >> 8) & 0xFF);
    bpf_debug(DBG_PACKET, "UL(XDP): IPv4 src: %u", ip_src & 0xFF);
    bpf_debug(DBG_PACKET, "UL(XDP): IPv4 dst: %u.%u.%u", (ip_dest >> 24) & 0xFF, (ip_dest >> 16) & 0xFF, (ip_dest >> 8) & 0xFF);
    bpf_debug(DBG_PACKET, "UL(XDP): IPv4 dst: %u", ip_dest & 0xFF);

    // For DL traffic, only record flow if dest IP was previously a UL source
    if (direction == DIRECTION_DL) {
        __u32 pkt_len = p_data_end - p_data;
        bpf_debug(DBG_PACKET, "DL(TC): DL traffic: checking if dest IP was UL source\n");
        
        // Check if destination IP exists in UL source IPs
        if (is_ul_source_ip(iph->daddr)) {
            bpf_debug(DBG_PACKET, "DL(TC): DL traffic: dest IP found in UL sources, recording outer flow\n");
            // For DL outer flow, use port 0 since we don't parse L4 headers
            record_flow(ctx, iph, iph->protocol, 0, 0, pkt_len);
        } else {
            bpf_debug(DBG_PACKET, "DL(TC): DL traffic: dest IP (%u.%u.%u", 
                      (bpf_ntohl(iph->daddr) >> 24) & 0xFF, (bpf_ntohl(iph->daddr) >> 16) & 0xFF, (bpf_ntohl(iph->daddr) >> 8) & 0xFF);
            bpf_debug(DBG_PACKET, "DL(TC): DL traffic: dest IP %u) not in UL sources, skipping flow record\n", 
                      bpf_ntohl(iph->daddr) & 0xFF);
        }
        return XDP_PASS;
    }

    // For UL traffic, continue deep parsing
    switch (iph->protocol) {
        case IPPROTO_UDP:
            bpf_debug(DBG_PACKET, "UL(XDP): UDP packet - UL traffic, continue parsing\n");
            struct udphdr *udp_hdr = (struct udphdr *)((void*)iph + sizeof(*iph));
            udp_handle(ctx, udp_hdr, direction);
            break;
        case IPPROTO_TCP:
            bpf_debug(DBG_PACKET, "UL(XDP): TCP packet - UL traffic\n");
            break;
        default:
            bpf_debug(DBG_PACKET, "UL(XDP): Unknown IPv4 protocol - UL traffic\n");
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
        bpf_debug(DBG_PACKET, "DL(TC): Invalid IPv4 header\n");
        return TC_ACT_OK;
    }
    
    __u32 ip_src = bpf_ntohl(iph->saddr);
    __u32 ip_dest = bpf_ntohl(iph->daddr);
    bpf_debug(DBG_PACKET, "DL(TC): IPv4 src: %u.%u.%u", (ip_src >> 24) & 0xFF, (ip_src >> 16) & 0xFF, (ip_src >> 8) & 0xFF);
    bpf_debug(DBG_PACKET, "DL(TC): IPv4 src: %u", ip_src & 0xFF);
    bpf_debug(DBG_PACKET, "DL(TC): IPv4 dst: %u.%u.%u", (ip_dest >> 24) & 0xFF, (ip_dest >> 16) & 0xFF, (ip_dest >> 8) & 0xFF);
    bpf_debug(DBG_PACKET, "DL(TC): IPv4 dst: %u", ip_dest & 0xFF);

    // For DL traffic, only record flow if dest IP was previously a UL source
    __u32 pkt_len = data_end - data;
    bpf_debug(DBG_PACKET, "DL(TC): checking if dest IP was UL source\n");
    
    // Check if destination IP exists in UL source IPs
    if (is_ul_source_ip(iph->daddr)) {
        bpf_debug(DBG_PACKET, "DL(TC): dest IP found in UL sources, recording outer flow\n");
        // For DL outer flow, use port 0 since we don't parse L4 headers in DL
        record_flow(skb, iph, iph->protocol, 0, 0, pkt_len);
    } else {
        bpf_debug(DBG_PACKET, "DL(TC): dest IP (%u.%u.%u", 
                  (bpf_ntohl(iph->daddr) >> 24) & 0xFF, (bpf_ntohl(iph->daddr) >> 16) & 0xFF, (bpf_ntohl(iph->daddr) >> 8) & 0xFF);
        bpf_debug(DBG_PACKET, "DL(TC): dest IP %u) not in UL sources, skipping flow record\n", 
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
        bpf_debug(DBG_PACKET, "UL(XDP): Invalid Ethernet header\n");
        return XDP_PASS;
    }

    __u16 eth_type = htons(ethh->h_proto);
    bpf_debug(DBG_PACKET, "UL(XDP): Ethernet type: 0x%x\n", eth_type);

    switch (eth_type) {
    case ETH_P_8021Q:
    case ETH_P_8021AD:
        bpf_debug(DBG_PACKET, "UL(XDP): IP VLAN -> Change the offset\n");
        struct vlan_hdr *vlan_hdr = (void*)(ethh + 1);
        offset += sizeof(struct vlan_hdr);
        
        // Check Validity of Length
        if ((void*)ethh + offset > p_data_end) {
            bpf_debug(DBG_PACKET, "UL(XDP): Invalid VLAN header\n");
            return XDP_PASS;
        }
        eth_type = htons(vlan_hdr->h_vlan_encapsulated_proto);

    case ETH_P_IP:
        bpf_debug(DBG_PACKET, "UL(XDP): IPv4 packet\n");
        struct iphdr *ip_hdr = (struct iphdr *)((void*)ethh + offset);
        return ipv4_handle(ctx, ip_hdr, direction);
        break;
    case ETH_P_IPV6:
        bpf_debug(DBG_PACKET, "UL(XDP): IPv6 packet\n");
        break;
    default:
        bpf_debug(DBG_PACKET, "UL(XDP): Unknown Ethernet type\n");
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
        bpf_debug(DBG_PACKET, "DL(TC): Invalid packet length for IP header\n");
        return TC_ACT_OK;
    }
    
    struct iphdr *iph = data;
    
    // Validate IP version
    if (iph->version != 4) {
        bpf_debug(DBG_PACKET, "DL(TC): Non-IPv4 packet (version=%d)\n", iph->version);
        return TC_ACT_OK;
    }
    
    bpf_debug(DBG_PACKET, "DL(TC): IPv4 packet detected\n");
    
    // Process DL traffic using TC IPv4 handling
    return tc_ipv4_handle(skb, iph);
}