#ifndef __EBPF_COMMON_H__
#define __EBPF_COMMON_H__

/**
 * @file ebpf_common.h
 * @brief Common definitions and constants for eBPF UPF programs
 */

#include <linux/bpf.h>
#include <linux/types.h>

/* ============================================================================
 * Program Return Codes
 * ============================================================================ */

/// XDP action codes
#define EBPF_XDP_PASS    XDP_PASS
#define EBPF_XDP_DROP    XDP_DROP
#define EBPF_XDP_ABORTED XDP_ABORTED

/// TC action codes  
#define EBPF_TC_OK       TC_ACT_OK
#define EBPF_TC_SHOT     TC_ACT_SHOT

/* ============================================================================
 * Protocol Constants
 * ============================================================================ */

/// Ethernet types
#define EBPF_ETH_P_IP    0x0800
#define EBPF_ETH_P_IPV6  0x86DD
#define EBPF_ETH_P_8021Q 0x8100

/// IP protocols
#define EBPF_IPPROTO_ICMP   1
#define EBPF_IPPROTO_TCP    6
#define EBPF_IPPROTO_UDP    17

/* ============================================================================
 * Utility Macros
 * ============================================================================ */

/// Check if pointer is within packet bounds
#define EBPF_BOUNDS_CHECK(ptr, size, end) \
    ((void*)(ptr) + (size) <= (void*)(end))

/// Convert network byte order to host byte order for debugging
#define EBPF_NTOHL_DEBUG(addr) \
    ((bpf_ntohl(addr) >> 24) & 0xFF), \
    ((bpf_ntohl(addr) >> 16) & 0xFF), \
    ((bpf_ntohl(addr) >> 8) & 0xFF), \
    (bpf_ntohl(addr) & 0xFF)

#endif /* __EBPF_COMMON_H__ */
