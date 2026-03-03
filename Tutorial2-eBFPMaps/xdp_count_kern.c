/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_helpers.h>

/* This is the data record stored in the map */
struct datarec {
 // TODO: Define the structure that will hold the packet and byte counters. 
 int rx_packets;
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
	// Task 1: Store in the map the total number of packets and bytes received on the interface.
	__u32 key = 0;
	struct datarec *rec;

	rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
	if (!rec)
		return XDP_PASS;
	rec->rx_packets += 1;
	/*
	* Hint: The structure `xdp_md` contains metadata about the packet being processed, including pointers to the start (ctx->data) and end (ctx->data_end) of the packet data. You can use these pointers to calculate the packet length, which is needed to update the byte counter. 
	*/

	/* 
	* Hint:To develop the XDP program, you can inspect the header file `../lib/xdp-tools/headers/linux/bpf.h` to find documentation for helper C functions. 
	* To access the record you can use the method bpf_map_lookup_elem  
	* void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)
	* 	Description
	* 		Perform a lookup in *map* for an entry associated to *key*.
	* 	Return
	* 		Map value associated to *key*, or **NULL** if no entry was
	* 		found.
	*
	* and assume that the key is always 0. 
*/

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
