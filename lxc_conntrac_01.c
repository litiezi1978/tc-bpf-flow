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
#include "lxc_conntrac.h"

static inline __u32 __inline__ ct_update_timeout(
        struct ct_entry *entry,
		__u32 input_lifetime,
        int dir,
        union tcp_flags flags)
{
	__u32 lifetime = input_lifetime;
	if(input_lifetime <0){
		__u32 lifetime = CT_CONNECTION_LIFETIME_NONTCP;
		bool syn = flags.value & TCP_FLAG_SYN;
		entry->seen_non_syn |= !syn;
		if (entry->seen_non_syn) {
			lifetime = CT_CONNECTION_LIFETIME_TCP;
		} else {
			lifetime = CT_SYN_TIMEOUT;
		}
	}

    __u32 now = bpf_ktime_get_sec();
    __u8 accumulated_flags;
    __u8 seen_flags = flags.lower_bits;
    __u32 last_report;

    entry->lifetime = now + lifetime;

	if (dir == CT_INGRESS) {
		accumulated_flags = READ_ONCE(entry->rx_flags_seen);
		last_report = READ_ONCE(entry->last_rx_report);
	} else {
		accumulated_flags = READ_ONCE(entry->tx_flags_seen);
		last_report = READ_ONCE(entry->last_tx_report);
	}
	seen_flags |= accumulated_flags;

	if (last_report + CT_REPORT_INTERVAL < now || accumulated_flags != seen_flags) {
		/* verifier workaround: we don't use reference here. */
		if (dir == CT_INGRESS) {
			WRITE_ONCE(entry->rx_flags_seen, seen_flags);
			WRITE_ONCE(entry->last_rx_report, now);
		} else {
			WRITE_ONCE(entry->tx_flags_seen, seen_flags);
			WRITE_ONCE(entry->last_tx_report, now);
		}
		return TRACE_PAYLOAD_LEN;
	}
	return 0;
}

static inline __u8 __inline__ ct_lookup(
		struct __sk_buff *skb,
		struct ipv4_ct_tuple *tuple,
		int action,
		int dir,
		union tcp_flags seen_flags)
{
	struct ct_entry *entry;
    int reopen;
    __u32 monitor = 0;

	if ((entry = map_lookup_elem(&CT_MAP_TCP4, tuple))) {
        if (ct_entry_alive(entry)) {
            monitor = ct_update_timeout(entry, -1,  dir, seen_flags);
        }

        if (dir == CT_INGRESS) {
        	__sync_fetch_and_add(&entry->rx_packets, 1);
            __sync_fetch_and_add(&entry->rx_bytes, skb->len);
        } else if (dir == CT_EGRESS) {
        	__sync_fetch_and_add(&entry->tx_packets, 1);
            __sync_fetch_and_add(&entry->tx_bytes, skb->len);
        }

        switch(action){
        case ACTION_CREATE:
            reopen = entry->rx_closing | entry->tx_closing;
            reopen |= seen_flags.value & TCP_FLAG_SYN;
            if (unlikely(reopen == (TCP_FLAG_SYN|0x1))) {
                ct_reset_closing(entry);
                monitor = ct_update_timeout(entry, -1, dir, seen_flags);
            }
            break;
        case ACTION_CLOSE:
            if (dir == CT_INGRESS){
                entry->rx_closing = 1;
            } else {
                entry->tx_closing = 1;
            }
            monitor = TRACE_PAYLOAD_LEN;
            if (ct_entry_alive(entry)){
                break;
            }
            ct_update_timeout(entry, CT_CLOSE_TIMEOUT, dir, seen_flags);
            break;
        }
		return CT_ESTABLISHED;
	}

    monitor = TRACE_PAYLOAD_LEN;
	return CT_NEW;
}

static inline int __inline__ ct_create4(
		struct ipv4_ct_tuple *tuple,
        struct __sk_buff *skb,
        int dir)
{
    struct ct_entry entry = {};
    union tcp_flags seen_flags = { .value = 0 };
    seen_flags.value |= TCP_FLAG_SYN;

    ct_update_timeout(&entry, -1, dir, seen_flags);

    if (dir == CT_INGRESS) {
        entry.rx_packets = 1;
        entry.rx_bytes = skb->len;
    } else if (dir == CT_EGRESS) {
        entry.tx_packets = 1;
        entry.tx_bytes = skb->len;
    }

    if (map_update_elem(&CT_MAP_TCP4, tuple, &entry, 0) < 0){
        return DROP_CT_CREATE_FAILED;
    }

	char msg1[] = "create conn track, srcIP=%d, dstIP=%d\n";
	bpf_trace_printk(msg1, sizeof(msg1), tuple->saddr, tuple->daddr);
	char msg2[] = "srcPort=%d, dstPort=%d\n";
	bpf_trace_printk(msg2, sizeof(msg2), tuple->sport, tuple->dport);

    return TC_ACT_OK;
}

static inline void __inline__ ipv4_ct_tuple_reverse(struct ipv4_ct_tuple *tuple)
{
    __be32 tmp_addr = tuple->saddr;
    __be16 tmp;

    tuple->saddr = tuple->daddr;
    tuple->daddr = tmp_addr;

    tmp = tuple->sport;
    tuple->sport = tuple->dport;
    tuple->dport = tmp;

    if (tuple->flags & TUPLE_F_IN) {
        tuple->flags &= ~TUPLE_F_IN;
    } else {
        tuple->flags |= TUPLE_F_IN;
    }
}

static inline int __inline__ handle_traffic(
		struct __sk_buff *skb,
		int dir)
{
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

    __u8 ret = ct_lookup(skb, &tuple, action, dir, tcp_flags);
    if(ret == CT_NEW){
    	//反着再查一遍
    	ipv4_ct_tuple_reverse(&tuple);
    	ret = ct_lookup(skb, &tuple, action, dir, tcp_flags);
    	if(ret == CT_NEW){
    		ret = ct_create4(&tuple, skb, dir);
    	}
    }

	return TC_ACT_OK;
}

__section("egress")
int handle_egress(struct __sk_buff *skb)
{
	return handle_traffic(skb, CT_EGRESS);
}

__section("ingress")
int handle_ingress(struct __sk_buff *skb)
{
	return handle_traffic(skb, CT_INGRESS);
}

char _license[] __section("license") = "GPL";
