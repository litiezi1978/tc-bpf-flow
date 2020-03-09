#ifndef common_h
#define common_h

#define DROP_INVALID_SIP	-132
#define DROP_POLICY		-133
#define DROP_INVALID		-134
#define DROP_CT_INVALID_HDR	-135
#define DROP_CT_UNKNOWN_PROTO	-137
#define DROP_UNKNOWN_L3		-139
#define DROP_MISSED_TAIL_CALL	-140
#define DROP_WRITE_ERROR	-141
#define DROP_UNKNOWN_L4		-142
#define DROP_UNKNOWN_ICMP_CODE	-143
#define DROP_UNKNOWN_ICMP_TYPE	-144
#define DROP_UNKNOWN_ICMP6_CODE	-145
#define DROP_UNKNOWN_ICMP6_TYPE	-146
#define DROP_NO_TUNNEL_KEY	-147
#define DROP_UNKNOWN_TARGET	-150
#define DROP_UNROUTABLE		-151
#define DROP_CSUM_L3		-153
#define DROP_CSUM_L4		-154
#define DROP_CT_CREATE_FAILED	-155
#define DROP_INVALID_EXTHDR	-156
#define DROP_FRAG_NOSUPPORT	-157
#define DROP_NO_SERVICE		-158
#define DROP_NO_TUNNEL_ENDPOINT -160
#define DROP_UNKNOWN_CT			-163
#define DROP_HOST_UNREACHABLE		-164
#define DROP_NO_CONFIG		-165
#define DROP_UNSUPPORTED_L2		-166
#define DROP_NAT_NO_MAPPING	-167
#define DROP_NAT_UNSUPP_PROTO	-168
#define DROP_NO_FIB		-169
#define DROP_ENCAP_PROHIBITED	-170
#define DROP_INVALID_IDENTITY	-171
#define DROP_UNKNOWN_SENDER	-172
#define DROP_NAT_NOT_NEEDED	-173

#define NSEC_PER_SEC	1000000000UL

#ifndef TRACE_PAYLOAD_LEN
#define TRACE_PAYLOAD_LEN 128ULL
#endif

#ifndef __READ_ONCE
#define __READ_ONCE(x) (*(volatile typeof(x) *)&x)
#endif

#ifndef __WRITE_ONCE
#define __WRITE_ONCE(x, v) (*(volatile typeof(x) *)&x) = (v)
#endif

/* {READ,WRITE}_ONCE() with verifier workaround via bpf_barrier(). */
#ifndef READ_ONCE
#define READ_ONCE(x) ({ typeof(x) __val; __val = __READ_ONCE(x); bpf_barrier(); __val; })
#endif

#ifndef WRITE_ONCE
# define WRITE_ONCE(x, v) ({ typeof(x) __val = (v); __WRITE_ONCE(x, __val); bpf_barrier(); __val; })
#endif

#define CT_EGRESS 0
#define CT_INGRESS 1

#ifndef CT_REPORT_INTERVAL
#define CT_REPORT_INTERVAL	5	/* 5 seconds */
#endif

#define CT_CONNECTION_LIFETIME_TCP	21600
#define CT_CONNECTION_LIFETIME_NONTCP 60
#define CT_SYN_TIMEOUT	60
#define CT_CLOSE_TIMEOUT 10

#define TUPLE_F_OUT	0	/* Outgoing flow */
#define TUPLE_F_IN	1	/* Incoming flow */

enum {
    ACTION_UNSPEC,
    ACTION_CREATE,
    ACTION_CLOSE,
};

enum {
    CT_NEW,
    CT_ESTABLISHED,
    CT_REPLY,
    CT_RELATED,
};

#if __BYTE_ORDER == __LITTLE_ENDIAN
# define __bpf_ntohs(x)		__builtin_bswap16(x)
# define __bpf_htons(x)		__builtin_bswap16(x)
# define __bpf_ntohl(x)		__builtin_bswap32(x)
# define __bpf_htonl(x)		__builtin_bswap32(x)
#elif __BYTE_ORDER == __BIG_ENDIAN
# define __bpf_ntohs(x)		(x)
# define __bpf_htons(x)		(x)
# define __bpf_ntohl(x)		(x)
# define __bpf_htonl(x)		(x)
#else
# error "Fix your __BYTE_ORDER?!"
#endif

#define bpf_htons(x) (__builtin_constant_p(x) ?	__constant_htons(x) : __bpf_htons(x))
#define bpf_ntohs(x) (__builtin_constant_p(x) ?	__constant_ntohs(x) : __bpf_ntohs(x))
#define bpf_htonl(x) (__builtin_constant_p(x) ?	__constant_htonl(x) : __bpf_htonl(x))
#define bpf_ntohl(x) (__builtin_constant_p(x) ?	__constant_ntohl(x) : __bpf_ntohl(x))

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


#endif
