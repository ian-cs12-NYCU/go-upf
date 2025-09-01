#ifndef __DEBUG_TOOL_H__
#define __DEBUG_TOOL_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Debug levels (bitmask) */
#define DBG_PACKET  (1u << 0)  // per-packet tracing
#define DBG_FLOW    (1u << 1)  // per-flow events


/* Single-element ARRAY map to hold debug bitmask.
 * key=0, value=bitmask of DBG_* above.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} debug_flags SEC(".maps");

/* Runtime-gated printk:
 * Use: bpf_debug(DBG_PACKET, "dst=%u.%u.%u.%u", a,b,c,d);
 * NOTE: bpf_printk allows up to 3 format args; if you need more, print twice
 * or pre-format with bpf_snprintf into a small stack buffer.
 */
#define bpf_debug(level, fmt, ...)                                           \
({                                                                           \
    __u32 __k = 0;                                                           \
    __u32 *__mask = bpf_map_lookup_elem(&debug_flags, &__k);                 \
    if (__mask && (*__mask & (level))) {                                     \
        bpf_printk(fmt, ##__VA_ARGS__);                                      \
    }                                                                         \
})

#endif /* __DEBUG_TOOL_H__ */
