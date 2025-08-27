
#ifndef __DEBUG_TOOL_H__
#define __DEBUG_TOOL_H__

#ifdef DEBUG
#define bpf_debug(fmt, ...)						\
		({							\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
				     ##__VA_ARGS__);			\
		})
#else
#define bpf_debug(fmt, ...) do {} while(0)
#endif


#endif