/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_helpers.h>

/* This is the data record stored in the map */
struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

/*
 * Per-CPU array with a single entry (key=0).
 * Each CPU updates its own copy of struct datarec.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct datarec);
} xdp_stats_map SEC(".maps");

SEC("xdp")
int xdp_count(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u32 key = 0;
	struct datarec *rec;
	__u64 bytes;

	bytes = data_end - data;

	rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
	if (!rec)
		return XDP_PASS;

	rec->rx_packets += 1;
	rec->rx_bytes += bytes;

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
