#if !defined(PROTOCOLS_GTP_H)
#define PROTOCOLS_GTP_H

/**
 * @file gtpu.h
 * @brief GTP-U (GPRS Tunneling Protocol User Plane) header definitions and utilities
 * 
 * This file defines structures and constants for handling GTP-U protocol packets
 * as specified in 3GPP TS 29.281. GTP-U is used to carry user data within the GPRS
 * Core Network and between the Radio Access Network and the Core Network.
 */

#include <linux/bpf.h>
#include <stdint.h>

/**
 * @brief Total size of GTP encapsulation (IP + UDP + GTP headers)
 * 
 * This constant defines the total overhead added when a packet is encapsulated
 * with GTP-U, including the outer IP header, UDP header, and GTP-U header.
 */
#define GTP_ENCAPSULATED_SIZE (sizeof(struct iphdr) +      \
                                sizeof(struct udphdr) +     \
                                sizeof(struct gtpuhdr))

/**
 * @brief Standard UDP port for GTP-U traffic (defined in 3GPP TS 29.281)
 */
#define GTP_UDP_PORT 2152u //!< TS 29 281

/**
 * @brief Default GTP flags value for GTPv1
 * 
 * Binary: 00110000
 * - Bits 8-6: Version (001 = v1)
 * - Bit 5: Protocol Type (1 = GTP)
 * - Bits 4-1: Reserved and extension bits
 */
#define GTP_FLAGS 0x30     //!< Version: GTPv1, Protocol Type: GTP, Others: 0 

/**
 * @brief GTP-U message types as defined in 3GPP TS 29.281 Section 6
 * 
 * These constants define the message types used in GTP-U protocol.
 * The most common type is G-PDU (255) which carries user data.
 */
// TS 29 281 - Section 6 GTP-U Message Formats
// Table 6.1-1: Messages in GTP-U
#define GTPU_ECHO_REQUEST (1)
#define GTPU_ECHO_RESPONSE (2)
#define GTPU_ERROR_INDICATION (26)
#define GTPU_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION (31)
#define GTPU_END_MARKER (254)
#define GTPU_G_PDU (255)

/**
 * @brief GTP-U message type for user data (T-PDU)
 * 
 * This is the most common message type for user plane data.
 */
#define GTPU_MSG_T_PDU    255

/**
 * @brief Bit masks for the first octet (flags) of GTP-U header
 * 
 * These masks allow extracting individual flag bits from the first byte
 * of the GTP-U header.
 */
/* flags bit mask (octet 1) */
#define GTPU_F_VER_MASK   0xE0  // Version (v1 -> 0x20)
#define GTPU_F_PT         0x10  // Protocol Type
#define GTPU_F_E          0x04  // Ext hdrs present
#define GTPU_F_S          0x02  // Sequence Number present
#define GTPU_F_PN         0x01  // N-PDU Number present

/**
 * @brief Length constants for GTP-U header components
 * 
 * The GTP-U header consists of a mandatory 8-byte fixed part,
 * and an optional 4-byte part that exists when any of the E, S, or PN flags are set.
 */
#define GTPU_BASE_LEN     8     // Fixed 8-byte mandatory header
#define GTPU_OPT_LEN      4     // Optional 4-byte extension (present if any of E|S|PN is set)


/**
 * @brief Fixed GTP-U header structure (8 bytes)
 * 
 * This structure represents the mandatory 8-byte header that exists in all GTP-U packets.
 * It uses a flat structure approach instead of bitfields to avoid endianness issues.
 * 
 * @note The structure is packed to ensure exact memory layout matching the protocol specification.
 */
struct gtpu_fixed {
    /**
     * @brief First byte containing version and flags
     * 
     * Bit layout: Ver(3)|PT(1)|0(1)|E(1)|S(1)|PN(1)
     * - Ver: Version bits (3 bits, value 001 for GTPv1)
     * - PT: Protocol Type (1 bit, value 1 for GTP)
     * - 0: Reserved bit (always 0)
     * - E: Extension header flag (1 if extension headers follow)
     * - S: Sequence number flag (1 if sequence number present)
     * - PN: N-PDU Number flag (1 if N-PDU number present)
     */
    __u8   flags;
    
    /**
     * @brief Message type (255 for user data/T-PDU)
     * 
     * This field indicates the type of GTP-U message.
     * For user data, the value is 255 (GTPU_G_PDU/GTPU_MSG_T_PDU).
     */
    __u8   msg_type;
    
    /**
     * @brief Message length in network byte order
     * 
     * This field indicates the length in octets of the payload following the mandatory
     * 8-byte GTP header. This includes the optional 4-byte header extension (if present),
     * any extension headers, and the actual user data (T-PDU).
     */
    __be16 msg_len;
    
    /**
     * @brief Tunnel Endpoint Identifier in network byte order
     * 
     * This field uniquely identifies a tunnel endpoint in the receiving GTP-U protocol entity.
     * The receiving end of a GTP tunnel assigns the TEID value that the transmitting side uses.
     * For certain message types (Echo Request/Response and Error Indication), TEID is set to 0.
     */
    __be32 teid;
} __attribute__((packed));

/**
 * @brief Optional GTP-U header extension (4 bytes)
 * 
 * This structure is present only when any of the E, S, or PN flags are set in the fixed header.
 * When present, it immediately follows the fixed 8-byte header.
 * 
 * @note The structure is packed to ensure exact memory layout matching the protocol specification.
 */
struct gtpu_opt {
    /**
     * @brief Sequence number in network byte order
     * 
     * This field is meaningful only when the S flag is set.
     * When S=0, this field should be ignored and is typically set to 0.
     */
    __be16 seq;
    
    /**
     * @brief N-PDU Number
     * 
     * This field is meaningful only when the PN flag is set.
     * When PN=0, this field should be ignored and is typically set to 0.
     */
    __u8   npdu;
    
    /**
     * @brief Next Extension Header Type
     * 
     * This field is meaningful only when the E flag is set.
     * It indicates the type of the first extension header that follows.
     * When E=0, this field should be ignored and is typically set to 0.
     */
    __u8   next_ext;
} __attribute__((packed));


/**
 * @brief Macro to process a single GTP-U extension header
 * 
 * This macro handles a single extension header in the GTP-U packet:
 * 1. Checks if there is a next extension header (next != 0)
 * 2. Validates the extension header length
 * 3. Ensures the packet has enough space for the extension header
 * 4. Updates pointers and counters for the next extension header
 * 
 * @param p Pointer to the current position in the packet
 * @param next Type of the next extension header (0 means no more extensions)
 * @param end Pointer to the end of the packet data
 * @param remain Remaining bytes in the GTP-U message length counter
 * 
 * @return Returns -1 on error (invalid extension header), otherwise continues processing
 */
#define GTPU_STEP_EXT_ONCE_BOUNDED(p, next, end, remain)                 \
    do {                                                                  \
        if ((next) != 0) {                                                \
            /* Check we have at least 1 byte to read the length */        \
            if ((p) + 1 > (end)) return -1;                               \
            __u8 __len4 = *(p);                                           \
            /* Length must be non-zero (unit is 4 bytes) */               \
            if (__len4 == 0) return -1;                                   \
            __u32 __ext_total = (__u32)__len4 * 4;                        \
            /* Extension header must be at least 4 bytes long */          \
            if (__ext_total < 4) return -1;                               \
            /* Ensure we have enough data for the entire extension */     \
            if ((p) + __ext_total > (end)) return -1;                     \
            /* Ensure the extension fits within the GTP message length */ \
            if ((remain) < __ext_total) return -1;                        \
            /* Get the next extension header type (last byte) */          \
            (next) = *((p) + __ext_total - 1);                            \
            /* Move pointer forward and reduce remaining bytes */         \
            (p) += __ext_total;                                           \
            (remain) -= __ext_total;                                      \
        }                                                                 \
    } while (0)


/**
 * @brief Locate the inner L3 (IP) header within a GTP-U packet
 * 
 * This function parses a GTP-U packet and returns a pointer to the beginning
 * of the encapsulated IP packet (inner L3 header). It handles all parts of
 * the GTP-U header, including:
 * 1. Fixed 8-byte header
 * 2. Optional 4-byte header (when E, S, or PN flags are set)
 * 3. Extension headers chain (when E flag is set)
 * 
 * @param g0 Pointer to the start of GTP-U header (first byte of UDP payload)
 * @param data_end Pointer to the end of the packet data
 * @param inner_out Output parameter: will be set to point to the inner L3 header
 * @param gtp_msg_len_out Optional output parameter: will be set to the GTP-U message length
 * @param gtpu_hdr_out Optional output parameter: will be set to point to the GTP-U fixed header
 * 
 * @return 0 on success, negative value on error (invalid GTP-U packet)
 */
static __always_inline int gtpu_locate_inner_l3(const void *g0,
                                                const void *data_end,
                                                const void **inner_out,
                                                __u16 *gtp_msg_len_out,
                                                const struct gtpu_fixed **gtpu_hdr_out)
{
    const __u8 *p   = (const __u8 *)g0;
    const __u8 *end = (const __u8 *)data_end;

    /* Process the fixed 8-byte GTP-U header */
    if (p + sizeof(struct gtpu_fixed) > end) return -1;
    const struct gtpu_fixed *g = (const struct gtpu_fixed *)p;
    
    /* If caller wants access to the GTP-U header, provide it */
    if (gtpu_hdr_out) *gtpu_hdr_out = g;
    
    p += sizeof(*g);

    /* Get the total message length after the 8-byte header */
    /* This includes optional 4-byte header, extension headers, and T-PDU */
    /* Use 'remain' to track remaining bytes as we process the headers */
    __u16 remain = bpf_ntohs(g->msg_len);
    if (gtp_msg_len_out) *gtp_msg_len_out = remain;

    /* Check for optional 4-byte header (present if any of E, S, or PN flags are set) */
    if (g->flags & (GTPU_F_E | GTPU_F_S | GTPU_F_PN)) {
        /* Ensure the message length includes the optional header */
        if (remain < sizeof(struct gtpu_opt)) return -1;
        /* Ensure the packet has enough space for the optional header */
        if (p + sizeof(struct gtpu_opt) > end) return -1;
        
        const struct gtpu_opt *opt = (const struct gtpu_opt *)p;
        p += sizeof(*opt);
        remain -= sizeof(*opt);

        /* Process extension headers if E flag is set */
        if (g->flags & GTPU_F_E) {
            __u8 next = opt->next_ext;

            /* Manually unroll the loop up to 6 times for eBPF verifier compatibility */
            /* This avoids unroll warnings and keeps the code verifier-friendly */
            GTPU_STEP_EXT_ONCE_BOUNDED(p, next, end, remain);  // Extension #1
            GTPU_STEP_EXT_ONCE_BOUNDED(p, next, end, remain);  // Extension #2
            GTPU_STEP_EXT_ONCE_BOUNDED(p, next, end, remain);  // Extension #3
            GTPU_STEP_EXT_ONCE_BOUNDED(p, next, end, remain);  // Extension #4
            GTPU_STEP_EXT_ONCE_BOUNDED(p, next, end, remain);  // Extension #5
            GTPU_STEP_EXT_ONCE_BOUNDED(p, next, end, remain);  // Extension #6
            
            /* If 'next' is still non-zero, there are more extensions than we can handle */
            if (next) return -1;  // Too many extensions or malformed packet
        }
    }

    /* p now points to the inner L3 (IPv4/IPv6) header */
    /* The caller should check the first byte to determine the IP version */
    *inner_out = (const void *)p;
    return 0;
}


#endif // PROTOCOLS_GTP_H