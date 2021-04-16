/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#define odbpf_vdebug(fmt, args...) \
({char ____fmt[] = fmt; bpf_trace_printk(____fmt, sizeof(____fmt), ##args); })

#define odbpf_debug(fmt, args...) odbpf_vdebug(fmt "\n", ##args)

/* Pops the outermost VLAN tag off the packet. Returns the popped VLAN ID on
 * success or -1 on failure.
 */
static __always_inline int vlan_tag_pop(struct xdp_md *ctx, struct ethhdr *eth)
{
	
	// void *data_end = (void *)(long)ctx->data_end;
	// struct ethhdr eth_cpy;
	// struct vlan_hdr *vlh;
	// __be16 h_proto;

	int vlid = -1;

	// /* Check if there is a vlan tag to pop */
	// if (!proto_is_vlan(h_proto)) {
	// 	odbpf_debug("does not contain a vlan tag");
	// 	return vlid;
	// }

	// /* Still need to do bounds checking */
	// vlh = nh->pos;
	// int vlanhdr_size = sizeof(*vlh);
	// if (nh->pos + vlanhdr_size > data_end) {
	// 	return -1;
	// }

	// /* Save vlan ID for returning, h_proto for updating Ethernet header */
	// vlh->h_vlan_TCI;


	/* Make a copy of the outer Ethernet header before we cut it off */

	/* Actually adjust the head pointer */

	/* Need to re-evaluate data *and* data_end and do new bounds checking
	 * after adjusting head
	 */

	/* Copy back the old Ethernet header and update the proto type */


	return vlid;
}

/* Pushes a new VLAN tag after the Ethernet header. Returns 0 on success,
 * -1 on failure.
 */
static __always_inline int vlan_tag_push(struct xdp_md *ctx,
					 struct ethhdr *eth, int vlid)
{
	return 0;
}

static __always_inline int handle_protocol(struct hdr_cursor *nh,
											int nh_type,
											void *data_end)
{
	if (nh_type == IPPROTO_UDP) {
		odbpf_debug("handle_protocol: udp found");
		struct udphdr *udph;
		int res = parse_udphdr(nh, data_end, &udph);
		odbpf_debug("parsed udphdr: %d", res);
		if (res == -1) {
			odbpf_debug("handle_protocol: parsing udp failed");
			return XDP_ABORTED;
		}
		udph->dest = bpf_htons(bpf_ntohs(udph->dest) - 1);
	} else if (nh_type == IPPROTO_TCP) {
		odbpf_debug("handle_protocol: tcp found");
		struct tcphdr *tcph;
		int res = parse_tcphdr(nh, data_end, &tcph);
		if (res == -1) {
			odbpf_debug("handle_protocol: parsing tcp failed");
			return XDP_ABORTED;
		}
		tcph->dest = bpf_htons(bpf_ntohs(tcph->dest) - 1);
	}
	return XDP_PASS;
}

/* Implement assignment 1 in this section */
SEC("xdp_port_rewrite")
int xdp_port_rewrite_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int nh_type;
	nh.pos = data;

	nh_type = parse_ethhdr(&nh, data_end, &eth);

	if (nh_type == bpf_htons(ETH_P_IPV6)) {
		odbpf_debug("nh_type is ipv6");
		struct ipv6hdr *ip6h;
		nh_type = parse_ip6hdr(&nh, data_end, &ip6h);
	} else if (nh_type == bpf_htons(ETH_P_IP)) {
		odbpf_debug("nh_type is ipv4");
		struct iphdr *iph;
		nh_type = parse_iphdr(&nh, data_end, &iph);
	} else {
		return XDP_PASS; // can't handle
	}

	return handle_protocol(&nh, nh_type, data_end);
}

/* VLAN swapper; will pop outermost VLAN tag if it exists, otherwise push a new
 * one with ID 1. Use this for assignments 2 and 3.
 */
SEC("xdp_vlan_swap")
int xdp_vlan_swap_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;

	struct ethhdr *eth;
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type < 0)
		return XDP_PASS;

	/* Assignment 2 and 3 will implement these. For now they do nothing */
	if (proto_is_vlan(eth->h_proto))
		vlan_tag_pop(ctx, eth);
	else
		vlan_tag_push(ctx, eth, 1);

	return XDP_PASS;
}

/* Solution to the parsing exercise in lesson packet01. Handles VLANs and legacy
 * IP (via the helpers in parsing_helpers.h).
 */
SEC("xdp_packet_parser")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;

	struct ethhdr *eth;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);

	if (nh_type == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h;
		struct icmp6hdr *icmp6h;

		nh_type = parse_ip6hdr(&nh, data_end, &ip6h);
		if (nh_type != IPPROTO_ICMPV6)
			goto out;

		nh_type = parse_icmp6hdr(&nh, data_end, &icmp6h);
		if (nh_type != ICMPV6_ECHO_REQUEST)
			goto out;

		if (bpf_ntohs(icmp6h->icmp6_sequence) % 2 == 0)
			action = XDP_DROP;

	} else if (nh_type == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph;
		struct icmphdr *icmph;

		nh_type = parse_iphdr(&nh, data_end, &iph);
		if (nh_type != IPPROTO_ICMP)
			goto out;

		nh_type = parse_icmphdr(&nh, data_end, &icmph);
		if (nh_type != ICMP_ECHO)
			goto out;

		if (bpf_ntohs(icmph->un.echo.sequence) % 2 == 0)
			action = XDP_DROP;
	}
 out:
	return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";
