#pragma clang diagnostic ignored "-Wcompare-distinct-pointer-types"

#include "include/api.h"
#include <bits/types.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>

#include "include/common.h"

static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) = (void *)BPF_FUNC_trace_printk;

static inline int __inline__ handle_traffic(struct __sk_buff *skb, int dir){
	void *data_end = (void*) (long) skb->data_end;
	void *data = (void*) (long) skb->data;

	struct ethhdr *l2_header_struct = data;
	__u64 l2_header_len = sizeof(*l2_header_struct);
	if (data + l2_header_len > data_end) {
		char msg1[] = "ethernet frame error!\n";
		bpf_trace_printk(msg1, sizeof(msg1));

		return TC_ACT_OK;
	}

	__u16 l3_proto = l2_header_struct->h_proto;

	if (l3_proto != bpf_htons(ETH_P_IP)) {
		return TC_ACT_OK;
	}

	struct iphdr *ip_header_struct = data + l2_header_len;
	if (ip_header_struct + 1 > data_end) {
		char msg3[] = "ip header out of memory!\n";
		bpf_trace_printk(msg3, sizeof(msg3));

		return TC_ACT_OK;
	}

	if (ip_header_struct->protocol != IPPROTO_TCP) {
		return TC_ACT_OK;
	}

	__u32 ip_header_len = ip_header_struct->ihl << 2;
	if (ip_header_len != sizeof(*ip_header_struct)) {
		char msg4[] = "ip header error!\n";
		bpf_trace_printk(msg4, sizeof(msg4));

		return TC_ACT_OK;
	}
	__u32 ip_total_length = ip_header_struct->tot_len;

	struct tcphdr *tcp_header_struct = data + l2_header_len + sizeof(*ip_header_struct);
	if (tcp_header_struct + 1 > data_end) {
		char msg5[] = "tcp header out of meeory!\n";
		bpf_trace_printk(msg5, sizeof(msg5));

		return TC_ACT_OK;
	}
	__u32 tcp_header_len = tcp_header_struct->doff << 2;

	struct ipv4_ct_tuple tuple = {};
	tuple.daddr = ip_header_struct->daddr;
	tuple.saddr = ip_header_struct->saddr;
	tuple.nexthdr = ip_header_struct->protocol;
	if (skb_load_bytes(skb, l2_header_len + ip_header_len, &tuple.sport, 4) < 0){
		char msg6[] = "cannot load sport dport from tcp header!\n";
		bpf_trace_printk(msg6, sizeof(msg6));

	    return TC_ACT_OK;
	}

	__u32 payload_offset = ETH_HLEN + ip_header_len + tcp_header_len;
	if(data + payload_offset > data_end){
		return TC_ACT_OK;
	}
	__u32 payload_length = ip_total_length - ip_header_len - tcp_header_len;
	if (payload_length >= 8) {
		__u8 p[8];
		int ret = skb_load_bytes(skb, payload_offset, p, 8);
		if (ret < 0){
			char msg7[] = "load payload err: ip_total_length=%d, ip_header_len=%d, tcp_header_len=%d\n";
			bpf_trace_printk(msg7, sizeof(msg7), ip_total_length, ip_header_len, tcp_header_len);

			return TC_ACT_OK;
		}

		if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T')) {
			char msg1[] = "HTTP GET request, srcIP=%d, dstIP=%d\n";
			bpf_trace_printk(msg1, sizeof(msg1), tuple.saddr, tuple.daddr);

			char msg2[] = "sport=%d, dport=%d\n";
			bpf_trace_printk(msg2, sizeof(msg2), bpf_htons(tuple.sport), bpf_htons(tuple.dport));

			return TC_ACT_OK;
		}

		if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) {
			char msg1[] = "HTTP Response, srcIP=%d, dstIP=%d\n";
			bpf_trace_printk(msg1, sizeof(msg1), tuple.saddr, tuple.daddr);

			char msg2[] = "sport=%d, dport=%d\n";
			bpf_trace_printk(msg2, sizeof(msg2), bpf_htons(tuple.sport), bpf_htons(tuple.dport));

			return TC_ACT_OK;
		}
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
