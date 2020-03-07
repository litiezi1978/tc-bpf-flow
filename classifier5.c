#pragma clang diagnostic ignored "-Wcompare-distinct-pointer-types"

#include "include/api.h"
#include <bits/types.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>

#include "include/common.h"

struct http_payload {
	int method;
};

static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) = (void *)BPF_FUNC_trace_printk;

static inline int __inline__ is_http(struct __sk_buff *skb, __u64 l2_header_len) {
	void *data_end = (void*) (long) skb->data_end;
	void *data = (void*) (long) skb->data;

	struct iphdr *ip_header_struct = data + l2_header_len;
	if (ip_header_struct + 1 > data_end) {
		return 0;
	}

	if (ip_header_struct->protocol != IPPROTO_TCP) {
		return 0;
	}

	__u32 ip_header_len = ip_header_struct->ihl << 2;
	if (ip_header_len < sizeof(*ip_header_struct)) {
		return 0;
	}
	__u32 ip_total_length = ip_header_struct->tot_len;

	struct tcphdr *tcp_header_struct = data + l2_header_len + sizeof(*ip_header_struct);
	if (tcp_header_struct + 1 > data_end) {
		return 0;
	}
	__u32 tcp_header_len = tcp_header_struct->doff << 2;

	struct ipv4_ct_tuple tuple = {};
	tuple.daddr = ip_header_struct->daddr;
	tuple.saddr = ip_header_struct->saddr;
	tuple.nexthdr = ip_header_struct->protocol;
	if (skb_load_bytes(skb, l2_header_len + sizeof(*ip_header_struct), &tuple.dport, 4) < 0){
	    return 0;
	}

	__u32 payload_offset = ETH_HLEN + ip_header_len + tcp_header_len;
	__u32 payload_length = ip_total_length - ip_header_len - tcp_header_len;
	if (payload_length >= 8) {
		__u8 p[8];
		int ret = skb_load_bytes(skb, payload_offset, p, 8);
		if (ret != 0){
			return 0;
		}

		if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T')) {
			char msg1[] = "srcIP=%d, dstIP=%d\n";
			bpf_trace_printk(msg1, sizeof(msg1), tuple.saddr, tuple.daddr);

			char msg2[] = "sport=%d, dport=%d\n";
			bpf_trace_printk(msg2, sizeof(msg2), bpf_htons(tuple.sport), bpf_htons(tuple.dport));

			return 1;
		}

		if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) {
			char msg1[] = "srcIP=%d, dstIP=%d\n";
			bpf_trace_printk(msg1, sizeof(msg1), tuple.saddr, tuple.daddr);

			char msg2[] = "sport=%d, dport=%d\n";
			bpf_trace_printk(msg2, sizeof(msg2), bpf_htons(tuple.sport), bpf_htons(tuple.dport));

			return 1;
		}
	}

	return 0;
}

__section("classifier")
int classification(struct __sk_buff *skb) {
	void *data_end = (void*) (long) skb->data_end;
	void *data = (void*) (long) skb->data;

	struct ethhdr *l2_header_struct = data;
	__u16 l3_proto;
	__u64 l2_header_len = 0;
	l2_header_len = sizeof(*l2_header_struct);

	if (data + l2_header_len > data_end) {
		return TC_ACT_OK;
	}

	l3_proto = l2_header_struct->h_proto;

	if (l3_proto == bpf_htons(ETH_P_IP)) {
		if (is_http(skb, l2_header_len) == 1) {
			char msg[] = "HTTP GET\n";
			bpf_trace_printk(msg, sizeof(msg));
		}
	}

	return TC_ACT_OK;
}

char _license[] __section("license") = "GPL";
