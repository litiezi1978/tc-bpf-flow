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

static inline int __inline__ is_http(struct __sk_buff *skb, __u64 nh_off) {
	void *data_end = (void*) (long) skb->data_end;
	void *data = (void*) (long) skb->data;
	struct iphdr *iph = data + nh_off;

	if (iph + 1 > data_end) {
		return 0;
	}

	if (iph->protocol != IPPROTO_TCP) {
		return 0;
	}

	__u32 tcp_hlen = 0;
	__u32 ip_hlen = 0;
	__u32 poffset = 0;
	__u32 plength = 0;
	__u32 ip_total_length = iph->tot_len;

	ip_hlen = iph->ihl << 2;

	if (ip_hlen < sizeof(*iph)) {
		return 0;
	}

	struct tcphdr *tcph = data + nh_off + sizeof(*iph);

	if (tcph + 1 > data_end) {
		return 0;
	}

	tcp_hlen = tcph->doff << 2;

	struct ipv4_ct_tuple tuple = {};
	tuple.daddr = iph->daddr;
	tuple.saddr = iph->saddr;
	tuple.nexthdr = iph->protocol;
	if (skb_load_bytes(skb, nh_off + sizeof(*iph), &tuple.dport, 4) < 0){
	    return 0;
	}

	poffset = ETH_HLEN + ip_hlen + tcp_hlen;
	plength = ip_total_length - ip_hlen - tcp_hlen;
	if (plength >= 8) {
		__u8 p[8];
		int ret = skb_load_bytes(skb, poffset, p, 8);
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
			return 1;
		}
	}

	return 0;
}

__section("classifier")
int classification(struct __sk_buff *skb) {
	void *data_end = (void*) (long) skb->data_end;
	void *data = (void*) (long) skb->data;
	struct ethhdr *eth = data;

	__u16 h_proto;
	__u64 nh_off = 0;
	nh_off = sizeof(*eth);

	char msg[] = "HTTP GET\n";

	if (data + nh_off > data_end) {
		return TC_ACT_OK;
	}

	h_proto = eth->h_proto;

	if (h_proto == bpf_htons(ETH_P_IP)) {
		if (is_http(skb, nh_off) == 1) {
			bpf_trace_printk(msg, sizeof(msg));
		}
	}

	return TC_ACT_OK;
}

char _license[] __section("license") = "GPL";
