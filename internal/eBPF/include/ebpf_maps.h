#ifndef __EBPF_MAPS_H__
#define __EBPF_MAPS_H__

/**
 * @file ebpf_maps.h
 * @brief eBPF map structures, definitions and data types for UPF packet processing
 * 
 * This file contains all the structure definitions and eBPF map definitions
 * used in the UPF programs for flow statistics, packet events, and source IP tracking.
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

/* ============================================================================
 * Constants and Definitions
 * ============================================================================ */

/// Maximum number of entries in maps
#define MAX_MAP_ENTRIES 16

/// Perf event configuration
#define WAKE_UP_INTERVAL 16              ///< Wake up every N events to reduce overhead

/// Direction constants for flow processing
#define DIRECTION_UL 1  ///< Uplink - need deep parsing (GTP tunneling)
#define DIRECTION_DL 2  ///< Downlink - shallow parsing (outer IP only)

/* ============================================================================
 * Data Structures for eBPF Maps
 * ============================================================================ */

/**
 * @brief Event structure for packet events (32-64 bytes, 8-byte aligned)
 * 
 * This structure represents packet events that are sent to userspace
 * via perf event array for monitoring and analytics.
 */
struct pkt_event {
    __u64 ts_ns;        ///< Timestamp (nanoseconds)
    __u32 saddr_v4;     ///< IPv4 source address
    __u32 daddr_v4;     ///< IPv4 destination address
    __u32 ifindex;      ///< Interface index
    __u16 sport;        ///< Source port
    __u16 dport;        ///< Destination port
    __u16 len;          ///< Packet length (L3 or L4)
    __u8 dir;           ///< Direction: DIRECTION_UL/DIRECTION_DL
    __u8 l4;            ///< L4 protocol: IPPROTO_TCP/UDP/ICMP
    __u8 tcp_flags;     ///< TCP flags (0 for non-TCP)
    __u8 dscp_ecn;      ///< DSCP/ECN from IP header
    __u8 ttl_hl;        ///< TTL/Hop Limit
    __u8 l3_frag;       ///< Fragment flags
    __u8 family;        ///< Address family (4=IPv4, 6=IPv6)
    __u8 reserved;      ///< Reserved for alignment
    // Total: 28 bytes, 8-byte aligned
} __attribute__((packed));

/**
 * @brief Configuration for packet sampling control
 * 
 * Controls how often packets are sampled and sent to userspace
 * to balance between monitoring granularity and performance.
 */
struct sampling_config {
    __u32 sample_rate;  ///< 1=all packets, 8=1/8 sampling, etc.
};

/**
 * @brief 5-tuple flow key for flow statistics tracking
 * 
 * This structure serves as the key in the flow statistics map,
 * uniquely identifying network flows by their 5-tuple.
 */
struct flow_key {
    __u8  family;       ///< 4: IPv4, 6: IPv6
    __u8  proto;        ///< IPPROTO_TCP/UDP/ICMP...
    __u16 pad;          ///< For alignment
    
    /**
     * @brief Address structure supporting both IPv4 and IPv6
     * 
     * For IPv4: only saddr and daddr are used
     * For IPv6: all four address fields are used
     */
    struct {
        __u32 saddr;    ///< v4 source address
        __u32 daddr;    ///< v4 destination address
        __u64 saddr_hi; ///< v6 high bits
        __u64 saddr_lo; ///< v6 low bits
        __u64 daddr_hi; ///< v6 high bits
        __u64 daddr_lo; ///< v6 low bits
    } addrs;
    
    __u16 sport;        ///< source port
    __u16 dport;        ///< destination port
};

/**
 * @brief Flow statistics data
 * 
 * Contains counters and timestamps for each tracked flow.
 */
struct flow_stats {
    __u64 packets;      ///< Packet count for this flow
    __u64 bytes;        ///< Byte count for this flow
    __u64 first_ts_ns;  ///< Timestamp of first packet
    __u64 last_ts_ns;   ///< Timestamp of last packet
    __u8 direction;     ///< Flow direction: DIRECTION_UL/DIRECTION_DL
    __u8 reserved[7];   ///< Reserved for alignment (padding to 8-byte boundary)
};

/**
 * @brief LPM trie key for IP address tracking
 * 
 * Used in LPM trie maps for prefix-based IP address lookups.
 * Supports both exact matches and subnet matches.
 */
struct ip_key {
    __u32 prefixlen;    ///< Prefix length (32 for exact match)
    __u32 addr;         ///< IPv4 address in network byte order
};

/**
 * @brief IP address statistics and metadata
 * 
 * Contains tracking information for source IP addresses
 * seen in uplink traffic.
 */
struct ip_info {
    __u64 first_seen_ts;    ///< First time this IP was seen
    __u64 last_seen_ts;     ///< Last time this IP was seen
    __u64 packet_count;     ///< Number of packets from this IP
    __u64 byte_count;       ///< Number of bytes from this IP
};

/* ============================================================================
 * eBPF Map Definitions
 * ============================================================================ */

/**
 * @brief Per-CPU counter for wake-up control
 * 
 * This map is used to control when to wake up userspace for processing
 * packet events, reducing the overhead of frequent wake-ups.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} event_counter SEC(".maps");

/**
 * @brief Per-CPU sampling counter for fair packet sampling
 * 
 * This map ensures reliable packet sampling by using per-CPU counters
 * instead of timestamp-based sampling, preventing sampling bias from
 * periodic traffic patterns.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} sampling_counter SEC(".maps");

/**
 * @brief Global event buffer using perf event array
 * 
 * This map is used to send packet events to userspace for monitoring
 * and analytics. Compatible with older kernels that don't support ring buffers.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 0);  ///< Will be set to number of CPUs by Go loader
    __type(key, __u32);
    __type(value, __u32);
} packet_events SEC(".maps");

/**
 * @brief Configuration map for sampling control
 * 
 * Controls packet sampling rate to balance between monitoring granularity
 * and performance impact.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sampling_config);
} sampling_control SEC(".maps");

/**
 * @brief LRU Hash for flow statistics tracking
 * 
 * Automatically evicts inactive flows to control memory usage.
 * Uses LRU (Least Recently Used) eviction policy.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);         ///< 128K entries - adjust based on node memory/traffic
    __type(key,   struct flow_key);
    __type(value, struct flow_stats);
} flow_statistics SEC(".maps");

/**
 * @brief LPM Trie for tracking UL source IPs
 * 
 * Uses Longest Prefix Match (LPM) trie for efficient IP address lookups.
 * Tracks source IPs that appear in uplink traffic for downlink correlation.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);             ///< 64K entries for source IPs
    __uint(map_flags, BPF_F_NO_PREALLOC);   ///< Dynamic allocation
    __type(key, struct ip_key);
    __type(value, struct ip_info);
} ul_source_ips SEC(".maps");

#endif /* __EBPF_MAPS_H__ */
