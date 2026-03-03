/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP packet/byte counter using a per-CPU eBPF map";

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"

/* This is the data record stored in the map 
 * TODO: make sure the structure has the same details as the kenrel version. */
struct datarec {
	__u64 rx_packets;
	__u64 rx_bytes;
};


static volatile bool exiting;

static void sigint_handler(int signo)
{
	(void)signo;
	exiting = true;
}

static const struct option_wrapper long_options[] = {
	{{"help", no_argument, NULL, 'h'}, "Show help", false},
	{{"dev", required_argument, NULL, 'd'}, "Operate on device <ifname>", "<ifname>", true},
	{{"skb-mode", no_argument, NULL, 'S'}, "Install XDP program in SKB (generic) mode"},
	{{"native-mode", no_argument, NULL, 'N'}, "Install XDP program in native mode"},
	{{"auto-mode", no_argument, NULL, 'A'}, "Auto-detect SKB or native mode"},
	{{"unload", required_argument, NULL, 'U'}, "Unload XDP program <id> instead of loading", "<id>"},
	{{"unload-all", no_argument, NULL, 4}, "Unload all XDP programs on device"},
	{{0, 0, NULL, 0}, NULL, false}};

static int get_stats_map_fd(struct xdp_program *prog)
{
	struct bpf_object *obj;
	struct bpf_map *map;
	int fd;

	// Get the underlying bpf_object from the xdp_program using the helper function from xdp-tools at common/common_user_bpf_xdp.c
	obj = xdp_program__bpf_obj(prog);
	if (!obj) {
		fprintf(stderr, "ERR: unable to get bpf_object from xdp_program\n");
		return -1;
	}

	// This name is the same as the one defined in the kernel code (struct definition of the map)
	map = bpf_object__find_map_by_name(obj, "xdp_stats_map");
	if (!map) {
		fprintf(stderr, "ERR: map 'xdp_stats_map' not found\n");
		return -1;
	}

	// Use the libbpf helper function to get the file descriptor for the map, which we will use to read values from the map in the main loop
	fd = bpf_map__fd(map);
	if (fd < 0) {
		fprintf(stderr, "ERR: bpf_map__fd failed: %s\n", strerror(errno));
		return -1;
	}

	return fd;
}

int main(int argc, char **argv)
{
	struct xdp_program *prog = NULL;
	struct config cfg = {
		.attach_mode = XDP_MODE_UNSPEC,
		.ifindex = -1,
		.do_unload = false,
	};
	const char filename[] = "xdp_count_kern.o";
	const char progname[] = "xdp_count";
	int map_fd = -1;
	int n_cpus;
	struct datarec *values = NULL;
	__u32 key = 0;
	int err;

	// Using the helper function from xdp-tools at common/common_params.h
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	// Unload program logic
	if (cfg.do_unload || cfg.unload_all) {

		// Unload logic is implemented in common/common_user_bpf_xdp.c
		err = do_unload(&cfg);
		if (err)
			fprintf(stderr, "ERR: unload failed (%d)\n", err);
		return err ? EXIT_FAIL_XDP : EXIT_OK;
	}

	// Use the hardcoded values to load the program and get the map fd
	strncpy(cfg.filename, filename, sizeof(cfg.filename));
	strncpy(cfg.progname, progname, sizeof(cfg.progname));

	// Simple logic to handle Ctrl-C and graceful shutdown
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	// Load the eBPF object and attach the XDP program using the helper function from xdp-tools at common/common_user_bpf_xdp.c
	prog = load_bpf_and_xdp_attach(&cfg);
	if (!prog)
		return EXIT_FAIL_BPF;

	// Get the file descriptor for the eBPF map using the helper function defined above
	map_fd = get_stats_map_fd(prog);
	if (map_fd < 0)
		return EXIT_FAIL_BPF;

	// Get the number of possible CPUs to allocate a per-CPU value buffer
	n_cpus = libbpf_num_possible_cpus();
	if (n_cpus < 0) {
		fprintf(stderr, "ERR: libbpf_num_possible_cpus failed\n");
		return EXIT_FAIL;
	}

	// Allocate a buffer to hold the per-CPU values for the map lookup. The size of the buffer is the number of possible CPUs multiplied by the size of the value type (struct datarec).
	values = calloc(n_cpus, sizeof(*values));
	if (!values) {
		fprintf(stderr, "ERR: failed to allocate per-CPU value buffer\n");
		return EXIT_FAIL;
	}

	printf("Running on %s (ifindex=%d). Press Ctrl-C to stop.\n", cfg.ifname, cfg.ifindex);

	while (!exiting) {

		// TODO: implement the logic to read the values from the map and aggregate the total packets and bytes across all CPUs. Then print the results to the console every second.

		// Hint: use bpf_map_lookup_elem() to read the values from the map, and remember that the map is a per-CPU array, so you will get an array of values (one for each CPU) that you need to aggregate. The total packets and bytes can be calculated by summing the rx_packets and rx_bytes fields across all CPU values. You can find details on how to access the map at https://docs.ebpf.io/linux/helper-function/bpf_map_lookup_elem/ 

		sleep(1);
	}

	free(values);

	/* Best-effort detach */
	err = xdp_program__detach(prog, cfg.ifindex, cfg.attach_mode, 0);
	if (err)
		fprintf(stderr, "WARN: detach failed: %s\n", strerror(-err));

	xdp_program__close(prog);
	return EXIT_OK;
}
