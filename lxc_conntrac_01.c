#pragma clang diagnostic ignored "-Wcompare-distinct-pointer-types"

#include "include/api.h"
#include <bits/types.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdbool.h>
#include "include/common.h"

#define IP_MF			0x2000
#define IP_OFFSET		0x1FFF

struct bpf_elf_map __section_maps CT_MAP_TCP4 = {
    .type		= BPF_MAP_TYPE_LRU_HASH,
    .size_key	= sizeof(struct ipv4_ct_tuple),
    .size_value	= sizeof(struct ct_entry),
    .pinning	= PIN_GLOBAL_NS,
    .max_elem	= 4096,
};

static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) = (void *)BPF_FUNC_trace_printk;

unsigned long long load_half(void *skb, unsigned long long off) asm("llvm.bpf.load.half");

static inline int ip_is_fragment(struct __sk_buff *skb, __u64 nhoff) {
	return load_half(skb, nhoff + offsetof(struct iphdr, frag_off)) & (IP_MF | IP_OFFSET);
}

static inline int __inline__ handle_traffic(struct __sk_buff *skb, int dir){
	void *data_end = (void*)(long) skb->data_end;
	void *data = (void*)(long) skb->data;

	struct ethhdr *l2_header_struct = data;
	__u64 l2_header_len = sizeof(*l2_header_struct);

	if (data + l2_header_len > data_end) {
		return TC_ACT_OK;
	}

	__u16 l3_proto = l2_header_struct->h_proto;
	if (l3_proto != bpf_htons(ETH_P_IP)) {
		return TC_ACT_OK;
	}

	struct iphdr *ip_header_struct = data + l2_header_len;
	if (ip_header_struct + 1 > data_end){
		return TC_ACT_OK;
	}

	if (ip_is_fragment(skb, l2_header_len)){
		return TC_ACT_OK;
	}

	if (ip_header_struct->protocol != IPPROTO_TCP) {
		return TC_ACT_OK;
	}

	__u32 ip_header_len = ip_header_struct->ihl * 4;
	if (ip_header_len != sizeof(*ip_header_struct)) {
		return TC_ACT_OK;
	}

	//__u32 ip_total_length = ip_header_struct->tot_len;

	struct tcphdr *tcp_header_struct = data + l2_header_len + ip_header_len;
	if (tcp_header_struct + 1 > data_end) {
		return TC_ACT_OK;
	}
	//__u32 tcp_header_len = tcp_header_struct->doff << 2;

	struct ipv4_ct_tuple tuple = {};
	tuple.daddr = ip_header_struct->daddr;
	tuple.saddr = ip_header_struct->saddr;
	tuple.nexthdr = ip_header_struct->protocol;
	if (skb_load_bytes(skb, l2_header_len + ip_header_len, &tuple.sport, 4) < 0){
	    return TC_ACT_OK;
	}
	if(dir == CT_EGRESS){
		tuple.flags = TUPLE_F_OUT;
	} else {
		tuple.flags = TUPLE_F_IN;
	}

	union tcp_flags tcp_flags = { .value = 0 };

    //tcp头里的第12个字节偏移，2个字节长，是TCP的状态标志位。4+6+6
    if (skb_load_bytes(skb, l2_header_len + ip_header_len + 12, &tcp_flags, 2) < 0){
        return TC_ACT_OK;
    }

    int action = ACTION_UNSPEC;
    if(unlikely(tcp_flags.value & (TCP_FLAG_RST|TCP_FLAG_FIN))){
    	action = ACTION_CLOSE;
    } else {
    	action = ACTION_CREATE;
    }

	return TC_ACT_OK;
}

__section("egress")
int handle_egress(struct __sk_buff *skb) {
	return handle_traffic(skb, CT_EGRESS);
}

__section("ingress")
int handle_ingress(struct __sk_buff *skb) {
	return handle_traffic(skb, CT_INGRESS);
}

char _license[] __section("license") = "GPL";
