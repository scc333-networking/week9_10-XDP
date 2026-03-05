/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "../common/xdp_stats_kern_user.h"
#include "../common/parsing_helpers.h"

/*
 * Activity overview:
 * - Safely parse Ethernet + IPv4
 * - Detect ICMP
 * - Apply a simple rate limit per source IPv4 address
 * - Keep PASS/DROP packet+byte statistics
 */

#define WINDOW_NS 1000000000ULL /* 1 second */
#define ICMP_PPS_LIMIT 5        /* allowed ICMP packets per second, per source */

/* Per-source rate limiting state. */
struct rl_state {
	struct bpf_spin_lock lock;
	__u64 window_start_ns;
	__u32 count;
	__u32 pad;
};

/*
 * Hash map: key is IPv4 source address (network byte order).
 * Using a spin lock in the value makes the update race-safe.
 *
 * Note: Some kernels don't support bpf_spin_lock with LRU map types.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, struct rl_state);
} icmp_rl_map SEC(".maps");


static __always_inline int icmp_should_drop(__u32 src_ip, __u64 now)
{
	struct rl_state *st;
	int drop = 0;

	st = bpf_map_lookup_elem(&icmp_rl_map, &src_ip);
	if (!st) {
		struct rl_state init = {};
		init.window_start_ns = now;
		init.count = 1;
		bpf_map_update_elem(&icmp_rl_map, &src_ip, &init, BPF_ANY);
		return drop;
	}

	bpf_spin_lock(&st->lock);
	if (now - st->window_start_ns > WINDOW_NS) {
		st->window_start_ns = now;
		st->count = 1;
	} else {
		st->count += 1;
	}
	drop = st->count > ICMP_PPS_LIMIT;
	bpf_spin_unlock(&st->lock);
	bpf_printk("src_ip=%x count=%d\n", src_ip, st->count);

	return drop;
}

SEC("xdp")
int xdp_icmp_ratelimit(struct xdp_md *ctx)
{	
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u32 src_ip = 0;
	int drop = 0;
	struct hdr_cursor nh = { .pos = data };
	struct ethhdr *eth;
	struct iphdr *ip;
	struct icmphdr *icmph;

	if (parse_ethhdr(&nh, data_end, &eth) == -1) {
		bpf_printk("Failed to parse Ethernet header\n");
		return XDP_PASS;

	}


	if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
		bpf_printk("Not an IPv4 packet\n");
		return XDP_PASS;
	}

	if (parse_iphdr(&nh, data_end, &ip) == -1) {
		bpf_printk("Failed to parse IP header\n");
		return XDP_PASS;
	}

	if (ip->protocol != IPPROTO_ICMP) {
		bpf_printk("Not an ICMP packet %04x\n", ip->protocol);
		return XDP_PASS;
	}

	if (parse_icmphdr(&nh, data_end, &icmph) == -1) {
		bpf_printk("Failed to parse ICMP header\n");
		return XDP_PASS;
	}

	src_ip = ip->saddr;
	drop = icmp_should_drop(src_ip, bpf_ktime_get_ns());

	return drop ? XDP_DROP : XDP_PASS;
}

char _license[] SEC("license") = "GPL";
