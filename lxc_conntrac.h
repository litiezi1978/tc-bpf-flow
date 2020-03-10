#ifndef lxc_conntrac_h
#define lxc_conntrac_h

#include "include/api.h"

union tcp_flags {
    struct {
        __u8 upper_bits;
        __u8 lower_bits;
        __u16 pad;
    };
    __u32 value;
};

struct ipv4_ct_tuple {
    __be32	daddr;
    __be32	saddr;
    __be16	sport;
    __be16	dport;
    __u8  nexthdr;
    __u8  flags;
} __attribute__((packed));

struct ct_entry {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 tx_bytes;
    __u32 lifetime;
    __u16 rx_closing:1,
          tx_closing:1,
          seen_non_syn:1,
          reserved:9;

    /* represents the OR of all TCP flags seen for the transmit/receive direction of this entry. */
    __u8  tx_flags_seen;
    __u8  rx_flags_seen;

    /* timestamp of the last time a monitor notification was sent for the transmit/receive direction. */
    __u32 last_tx_report;
    __u32 last_rx_report;
};

struct bpf_elf_map __section_maps CT_MAP_TCP4 = {
    .type		= BPF_MAP_TYPE_LRU_HASH,
    .size_key	= sizeof(struct ipv4_ct_tuple),
    .size_value	= sizeof(struct ct_entry),
    .pinning	= PIN_GLOBAL_NS,
    .max_elem	= 4096,
};

static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) = (void *)BPF_FUNC_trace_printk;

unsigned long long load_half(void *skb, unsigned long long off) asm("llvm.bpf.load.half");

#define IP_MF			0x2000
#define IP_OFFSET		0x1FFF

static inline int ip_is_fragment(struct __sk_buff *skb, __u64 nhoff)
{
	return load_half(skb, nhoff + offsetof(struct iphdr, frag_off)) & (IP_MF | IP_OFFSET);
}

static inline __u32 bpf_ktime_get_sec(void)
{
    /* Ignores remainder subtraction as we'd do in ns_to_timespec(), but good enough here.*/
    return (__u64)(ktime_get_ns() / NSEC_PER_SEC);
}

static inline bool __inline__ ct_entry_alive(const struct ct_entry *entry)
{
    return !entry->rx_closing || !entry->tx_closing;
}

static inline void __inline__ ct_reset_closing(struct ct_entry *entry)
{
    entry->rx_closing = 0;
    entry->tx_closing = 0;
}

static inline uint64_t __inline__ ntoh64(const uint64_t *input)
{
    uint64_t rval;
    uint8_t *data = (uint8_t *)&rval;

    data[0] = *input >> 56;
    data[1] = *input >> 48;
    data[2] = *input >> 40;
    data[3] = *input >> 32;
    data[4] = *input >> 24;
    data[5] = *input >> 16;
    data[6] = *input >> 8;
    data[7] = *input >> 0;

    return rval;
}

#endif
