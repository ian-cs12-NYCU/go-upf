// #include <bpf/bpf_helpers.h>

// #define ip_u8_1(x) (((x) >> 24) & 255)
// #define ip_u8_2(x) (((x) >> 16) & 255)
// #define ip_u8_3(x) (((x) >>  8) & 255)
// #define ip_u8_4(x) ( (x)        & 255)

// static inline void dbg_ipv4_be(const char *label, __u32 ip_be)
// {
//     __u32 h = bpf_ntohl(ip_be);
// #if defined(HAVE_BPF_TRACE_VPRINTK)
//     char fmt[] = "%s %u.%u.%u.%u";
//     __u64 args[5];
//     args[0] = (unsigned long)label;
//     args[1] = ip_u8_1(h);
//     args[2] = ip_u8_2(h);
//     args[3] = ip_u8_3(h);
//     args[4] = ip_u8_4(h);
//     bpf_trace_vprintk(fmt, args, sizeof(args));
// #else
//     bpf_printk("%s %u.%u.%u", label, ip_u8_1(h), ip_u8_2(h), ip_u8_3(h));
//     bpf_printk("%s %u",       label, ip_u8_4(h));
// #endif
// }


// static inline void dbg_ipv4_host(const char *label, __u32 ip_host)
// {
// #if defined(HAVE_BPF_TRACE_VPRINTK)
//     char fmt[] = "%s %u.%u.%u.%u";
//     __u64 args[5] = { (unsigned long)label,
//                       ip_u8_1(ip_host), ip_u8_2(ip_host), ip_u8_3(ip_host), ip_u8_4(ip_host) };
//     bpf_trace_vprintk(fmt, args, sizeof(args));
// #else
//     bpf_printk("%s %u.%u.%u", label, ip_u8_1(ip_host), ip_u8_2(ip_host), ip_u8_3(ip_host));
//     bpf_printk("%s %u",       label, ip_u8_4(ip_host));
// #endif
// }
