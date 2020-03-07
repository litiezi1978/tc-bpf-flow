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


struct ipv4_ct_tuple {
    __be32	daddr;
    __be32	saddr;
    __be16	sport;
    __be16	dport;
    __u8  nexthdr;
    __u8  flags;
} __attribute__((packed));

#endif
