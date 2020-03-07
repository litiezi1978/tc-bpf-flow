#pragma clang diagnostic ignored "-Wcompare-distinct-pointer-types"

#include "include/api.h"
#include <bits/types.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <stdbool.h>
#include <stdio.h>

#include "include/common.h"

static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) = (void *)BPF_FUNC_trace_printk;

__section("classifier")
int classification(struct __sk_buff *skb) {
	char msg1[] = "l2 header wrong!\n";
	//char msg2[] = "HTTP GET srcIP=%d, dstIP=%d\n";
	char msg3[] = "HTTP RESP srcIP=%d, dstIP=%d\n";
	//char msg4[] = "TCP conn: %d %d %d\n";

	void *data = (void*) (long) skb->data;
	void *data_end = (void*) (long) skb->data_end;

	//check L2
	struct ethhdr *l2_header_struct = data;
	__u64 l2_header_length= ETH_HLEN;
	if(data + l2_header_length > data_end || sizeof(*l2_header_struct) != ETH_HLEN) {
		bpf_trace_printk(msg1, sizeof(msg1));
		return -1;
	}

	//check L3
	__u16 l3_protocol = l2_header_struct->h_proto;
	if(l3_protocol != bpf_htons(ETH_P_IP)) {
		return -2;
	}

	struct iphdr *l3_header_struct = data + l2_header_length;
	if(l3_header_struct + sizeof(*l3_header_struct) > data_end){
		return -3;
	}
	int l3_header_length = l3_header_struct->ihl * 4;
	if(l3_header_length < sizeof(*l3_header_struct)){
		return -4;
	}
	__u32 l3_total_length = l3_header_struct->tot_len;

	//check L4
	__u8 l4_protocol = l3_header_struct->protocol;
	if(l4_protocol != IPPROTO_TCP){
		return 0;
	}

	struct tcphdr * tcp_header_struct = data + l2_header_length + l3_header_length;
	if(tcp_header_struct + sizeof(*tcp_header_struct) > data_end){
		return -1;
	}
	__u32 tcp_header_length = tcp_header_struct->doff << 2;
	__u32 tcp_payload_length = l3_total_length - l3_header_length - tcp_header_length;

	struct ipv4_ct_tuple tuple = {};
    tuple.nexthdr = l4_protocol;
    tuple.daddr = l3_header_struct->daddr;
    tuple.saddr = l3_header_struct->saddr;

    //这里实际上把tuple的dport和sport全部都赋值了。
    if (skb_load_bytes(skb, tcp_header_length, &tuple.dport, 4) < 0){
    	return -5;
    }

	if (tcp_payload_length >= 8) {
		__u8 p[8];
		int ret = skb_load_bytes(skb, l2_header_length + l3_header_length + tcp_header_length, p, 8);
		if (ret != 0){
			return 0;
		}

//		bpf_trace_printk(msg4, sizeof(msg4), p[0], p[1], p[2]);

//		if((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T')){
//			bpf_trace_printk(msg2, sizeof(msg2), tuple.saddr, tuple.daddr);
//			return 0;
//		}

		if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) {
		    bpf_trace_printk(msg3, sizeof(msg3), tuple.saddr, tuple.daddr);
			return 0;
		}
	}

	return 0;
}

char _license[] __section("license") = "GPL";
