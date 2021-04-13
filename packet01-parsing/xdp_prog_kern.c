/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/icmpv6.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#define odbpf_vdebug(fmt, args...) \
({char ____fmt[] = fmt; bpf_trace_printk(____fmt, sizeof(____fmt), ##args); })

#define odbpf_debug(fmt, args...) odbpf_vdebug(fmt "\n", ##args)


/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

/* vlan header copied out of kernel as it is not exported */
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD));
}

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;

	__be16 proto = eth->h_proto;

	/* 
	service vlan can wrap customer vlan 
	check nested vlan headers 2 deep
	*/
	if (proto_is_vlan(proto)) {

		odbpf_debug("h_proto is vlan");
		struct vlan_hdr *maybe_vlan = nh->pos;
		int vlanhdr_size = sizeof(*maybe_vlan);

		if (nh->pos + vlanhdr_size > data_end) {
			return -1;
		}
		nh->pos += vlanhdr_size;
		proto = maybe_vlan->h_vlan_encapsulated_proto;

		if (proto_is_vlan(proto)) {

			odbpf_debug("h_proto is vlan");
			struct vlan_hdr *maybe_vlan = nh->pos;
			int vlanhdr_size = sizeof(*maybe_vlan);

			if (nh->pos + vlanhdr_size > data_end) {
				return -1;
			}
			nh->pos += vlanhdr_size;
			proto = maybe_vlan->h_vlan_encapsulated_proto;

		} else {
			odbpf_debug("not vlan");
		}

	} else {
		odbpf_debug("not vlan");
	}
	odbpf_debug("proto: %d", bpf_htons(proto));
	return proto; /* convert to network-byte-order */
}

/* Assignment 2: Implement and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ip6h = nh->pos;
	int hdrsize = sizeof(*ip6h);
	
	/* Pointer-arithmetic bounds check; pointer +1 points to after end of
	 * thing being pointed to. We will be using this style in the remainder
	 * of the tutorial.
	 */
	if (ip6h + 1 > data_end)
		return -1;

	nh->pos += hdrsize;
	*ip6hdr = ip6h;

	return ip6h->nexthdr;
}

/* Assignment 3: Implement and use this */
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{

	struct icmp6hdr *icmp6h = nh->pos;
	
	if(icmp6h + 1 > data_end) {
		// odbpf_debug("too large");
		return -1;
	}
		

	if(icmp6h->icmp6_type != ICMPV6_ECHO_REQUEST) {
		// odbpf_debug("not an echo request");
		return -1;
	}

	return icmp6h->icmp6_sequence;
}

static __always_inline int parse_ip4hdr(struct hdr_cursor *nh,
										void *data_end,
										struct iphdr **ip4hdr)
{
	struct iphdr *ip4h = nh->pos;
	int hdrsize = sizeof(*ip4h);

	if (ip4h + 1 > data_end) {
		odbpf_debug("doesn't fit into data");
		return -1;
	}
	
	hdrsize = ip4h->ihl * 4;
	if (nh->pos + hdrsize > data_end) {
		odbpf_debug("length of ip4 header doesn't fit");
		return -1;
	}

	nh->pos += hdrsize;
	*ip4hdr = ip4h;

	return ip4h->protocol;
}

static __always_inline int parse_icmp4hdr(struct hdr_cursor *nh,
										void *data_end,
										struct icmphdr **icmp4hdr)
{
	struct icmphdr *icmph = nh->pos;

	if(icmph + 1 > data_end) {
		// odbpf_debug("too large");
		return -1;
	}

	if(icmph->type != ICMP_ECHO) {
		odbpf_debug("not an ICMP_ECHO request");
		return -1;
	}

	return icmph->un.echo.sequence;
}										
										

SEC("xdp_packet_parser")
int xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	struct ipv6hdr *ip6hdr;
	struct iphdr *ip4hdr;
	struct icmp6hdr *icmp6h;
	struct icmphdr *icmph;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int res;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	res = parse_ethhdr(&nh, data_end, &eth);
	
	/* leave if not ipv6 or ip */
	if (res != bpf_htons(ETH_P_IPV6)) {
		odbpf_debug("res != ETH_P_IPV6");
		if (res != bpf_htons(ETH_P_IP)) {
			odbpf_debug("res != ETH_P_IP");
			goto out;
		}
	}
		
	odbpf_debug("res = %d", bpf_htons(res));

	/* Assignment additions go below here */
	if (res == bpf_htons(ETH_P_IPV6)) {
		res = parse_ip6hdr(&nh, data_end, &ip6hdr);
		if (res != IPPROTO_ICMPV6) {
			odbpf_debug("ip6hdr res = %d", res);
			odbpf_debug("res != IPPROTO_ICMPV6");
			goto out;
		}
		res = parse_icmp6hdr(&nh, data_end, &icmp6h);
		if (res == -1) {
			// odbpf_debug("res == -1");
			action = XDP_ABORTED;
		}	
		else if (bpf_ntohs(res) % 2 == 0) {
			// odbpf_debug("res is even: %d", res);
			action = XDP_DROP;
		}
	} else {
		/* must be ip header not ipv6 */
		odbpf_debug("treating as ip4");
		res = parse_ip4hdr(&nh, data_end, &ip4hdr);
		if (res != IPPROTO_ICMP) {
			odbpf_debug("ip4hdr res = %d", res);
			odbpf_debug("res != IPPROTO_ICMP");
			goto out;
		}
		res = parse_icmp4hdr(&nh, data_end, &icmph);
		if (res == -1) {
			odbpf_debug("res == -1");
			action = XDP_ABORTED;
		}	
		else if (bpf_ntohs(res) % 2 == 0) {
			// odbpf_debug("res is even: %d", res);
			action = XDP_DROP;
		}
	}
	

	odbpf_debug("res = %d", res);

	
		
out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
