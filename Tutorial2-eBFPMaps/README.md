# Lab: Counting packets and bytes with eBPF maps (XDP)

## Prerequisites and quick environment check

Before starting, confirm your environment is ready:

```sh
uname -r
bpftool version
xdp-loader --help
make
```

You should have:

- A kernel with eBPF/XDP support.
- `bpftool` and `xdp-loader` available in `PATH`.
- The project builds without errors.

If any command fails, fix tooling first before debugging BPF code.

If you want a quick refresher before you start:

- XDP overview: [https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_XDP/](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_XDP/)
- eBPF concepts (maps, helpers, verifier): [https://ebpf.io/what-is-ebpf/](https://ebpf.io/what-is-ebpf/)

## Overview

In this lab you will build an XDP/eBPF program that counts how many packets (and how many bytes) arrive on a network interface. The key constraint is that eBPF programs cannot keep normal global variables, so you will store your counters in an eBPF map in the kernel and then read those counters from user space. eBPF maps look a bit like the P4 register concept. They are a kernel-managed key/value store with a fixed type and capacity. You can define maps in your eBPF program, and the kernel will create and manage them for you. Fuerthermore, the kernel offers a range of different map types (array, hash, per-CPU variants, etc.) that you can choose from based on your use case to support not only simple state storage but also more complex operations, like lookups and aggregations.

By the end you will have two artifacts: a kernel-side XDP program that updates counters once per packet, and a user-space program that attaches the XDP program and prints the aggregated counters once per second.

## Learning outcomes

After completing this activity, a student should be able to explain what an eBPF map is (a kernel-managed key/value store with a fixed type and capacity), justify why per-CPU maps are useful for high-rate counters, and implement the full “kernel updates + user-space readout” loop for packet and byte counters.

> This tutorial uses both mininet and the terminal on your local devcontainer. When a command is expected to run on the devcontainer, we will prepend it with the prompt `$`. When a command is expected to run on the mininet host, we will prepend it with `mininet >`.

## eBPF maps: the kernel’s key/value store

An eBPF map is a kernel-resident data structure exposed as a generic key/value store. An eBPF program can initialize and update map entries to store state and persist it across packets. Drawing on our earlier discussion of P4 stateful memories, you can think of eBPF maps as a more general and flexible version of P4 registers, with a richer set of types and access patterns. Similarly, maps can also be used to store lookup tables, such as routing tables or access control lists, which can be updated dynamically by user-space programs. Nonetheless, for the latter, you need to implement the lookup code in your eBPF program.

Each map is defined by metadata (its “shape”) and by its contents. An eBPF program can define a map using a special syntax that libbpf understands, which allows the map to be automatically created and managed by the kernel. An eBPF map definition includes the following components:

- Type: how entries are stored (e.g., array vs hash vs per-CPU variants).
- Key type: the bytes that identify an entry (e.g., `__u32`, or a struct).
- Value type: the bytes stored per key (often a struct of counters).
- `max_entries`: the capacity of the map.
- `flags`: optional behavior controls (vary by map type).

Further reading:

- All BPF map types: [https://docs.ebpf.io/linux/map-type/](https://docs.ebpf.io/linux/map-type/)
- `BPF_MAP_TYPE_PERCPU_ARRAY`: [https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_PERCPU_ARRAY/](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_PERCPU_ARRAY/)
- `bpf_map_lookup_elem` helper: [https://docs.ebpf.io/linux/helper-function/bpf_map_lookup_elem/](https://docs.ebpf.io/linux/helper-function/bpf_map_lookup_elem/)
- `bpf_map_update_elem` helper: [https://docs.ebpf.io/linux/helper-function/bpf_map_update_elem/](https://docs.ebpf.io/linux/helper-function/bpf_map_update_elem/)

The definition is typically placed in the kernel-side C code and uses a special syntax that libbpf understands. For example, to define a per-CPU array map with one entry, you can write:

```c
struct datarec {
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct datarec);
} xdp_stats_map SEC(".maps");
```

The previous code snippet defines a map named `xdp_stats_map` that is a per-CPU array (each eBPF program instance on a CPU has its own copy) with a single entry (key `0`) where the value is of type `struct datarec`. This map can be used to store packet and byte counters that are updated by an XDP program on each packet. The per-CPU nature of the map allows for efficient updates without locking, as each CPU has its own copy of the counters, and user space can aggregate them when reading.

Inside eBPF programs, maps are accessed via helper functions such as `bpf_map_lookup_elem(&map, &key)` (returns a pointer to the value, or `NULL`) and `bpf_map_update_elem(&map, &key, &value, flags)` (insert/replace). From user space, maps are accessed via a file descriptor (FD) obtained after loading the object (or by opening a pinned map in bpffs).

For the development of BPF code, we rely on the libbpf library, which provides a convenient API for defining maps and loading programs. You can find the source code under folder `lib/libbpf`. It is worth keeping the file `lib/libbpf/src/bpf_helper_defs.h` open, as it contains the definitions of map macros and helper functions that you will use in your code.

Further reading:

- libbpf API docs: [https://libbpf.readthedocs.io/](https://libbpf.readthedocs.io/)
- libbpf source (`bpf_helper_defs.h`): [lib/libbpf/src/bpf_helper_defs.h](../lib/libbpf/src/bpf_helper_defs.h)

### Which map type should we use for counters?

Counters are updated at packet rate and XDP runs concurrently across CPUs. If multiple CPUs update the same memory location without coordination, increments can be lost. Your options are:

- Use a shared map (e.g., `BPF_MAP_TYPE_ARRAY`) with **atomic increments** — correct, but can slow down under high contention.
- Use a **per-CPU map** (e.g., `BPF_MAP_TYPE_PERCPU_ARRAY`) — each CPU has its own copy, user space sums them.

Further reading on concurrency in eBPF:

- eBPF concurrency concepts: [https://docs.ebpf.io/linux/concepts/concurrency/](https://docs.ebpf.io/linux/concepts/concurrency/)

If two CPUs update the same counter at the same time, you can lose updates unless you use atomic operations on shared counters, which can slow down your code due to locking. A per-CPU map avoids this contention by giving each CPU a private copy, and user space later sums the per-CPU values.

In this lab you will use a `BPF_MAP_TYPE_PERCPU_ARRAY` with a single entry at key `0`, where the value is a struct containing `rx_packets` and `rx_bytes`.

## Task 1 — Define the map in your XDP program

> The BPF runtime is designed to ensure that code is efficient and secure. That means resources are allocated when they are actually used, while the OS rejects unsafe operations. The provided code template can be compiled, but the loader will **fail to load** the program because the map definition is incomplete. It is normal that the default program fails.

In the provided code template, we include the struct used to define the map entry. This consists of a PER-CPU array map with one entry, where the value is a struct called `datarec`.

```C
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct datarec);
} xdp_stats_map SEC(".maps");
```

The `datarec` structure is currently empty. You should first define what data to store in the map.

```sh
$ make
$ make start
mininet > h1 xdp-loader load -m skb h1-eth0 xdp_icmp_count_kern.o --prog-name xdp_count_func
mininet > h1 xdp-loader status -d h1-eth0
```

### Expected result (Task 1)

- The program loads successfully with `xdp-loader`.
- `bpftool map show` lists `xdp_stats_map` as `percpu_array`.
- `max_entries` is `1` and key size is `4B` (`__u32`).

### Activity 2 — Update the map once per packet in your XDP program

In this second step, you will use your XDP program to update the map on every packet. Every time the XDP program runs (once per packet), the kernel passes a context pointer (`ctx`) that contains metadata about the packet and the processing environment. The content of the context is defined by the kernel and can vary based on the hook point (e.g., XDP, kprobe, tracepoint). For XDP programs, the context typically includes pointers to the packet data (`ctx->data` and `ctx->data_end`), as well as metadata such as the ingress interface index (`ctx->ingress_ifindex`) and other fields.

```C
/* user accessible metadata for XDP packet hook
 * new fields must be added to the end of this structure
 */
struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	/* Below access go through struct xdp_rxq_info */
	__u32 ingress_ifindex; /* rxq->dev->ifindex */
	__u32 rx_queue_index;  /* rxq->queue_index  */

	__u32 egress_ifindex;  /* txq->dev->ifindex */
};
```

You can use this context to access the packet data and compute its length in bytes. Then look up the map entry at key `0` and increment the `rx_packets` and `rx_bytes` counters.

> **Note:** Because the map value is a struct, a pointer returned by `bpf_map_lookup_elem` lets you update fields directly — you do not need to call `bpf_map_update_elem`.

Further reading:

- `bpf_map_lookup_elem`: [https://docs.ebpf.io/linux/helper-function/bpf_map_lookup_elem/](https://docs.ebpf.io/linux/helper-function/bpf_map_lookup_elem/)
- `struct xdp_md` context fields: [https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_XDP/](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_XDP/)

Implement the XDP handler so that on every packet it:

- gets a pointer to the `datarec` entry at key `0`
- reads `ctx->data` and `ctx->data_end` to compute the packet length
- increments `rx_packets` and `rx_bytes`


If you now build your program, you can use `bpftool` to inspect the loaded map and see its metadata (type, key/value sizes, etc.) and contents (initially zeroed). This will confirm that your map is defined correctly and is ready to be used by your XDP program.

```bash
mininet > h1 bpftool map show
mininet > h1 bpftool map dump id <map_id>
```

For example, the outputs for a sample run are the following:

```bash
mininet > h1 bpftool map show
...
23: perf_event_array  name events  flags 0x0
        key 4B  value 4B  max_entries 8  memlock 328B
181: percpu_array  name xdp_stats_map  flags 0x0
        key 4B  value 4B  max_entries 1  memlock 336B
        btf_id 316
mininet> h1 bpftool map dump id 181
[{
        "key": 0,
        "values": [{
                "cpu": 0,
                "value": {
                    "rx_packets": 0,
					"rx_bytes": 0
                }
            },{
                "cpu": 1,
                "value": {
                    "rx_packets": 0, 
					"rx_bytes": 0
                }
            },
....
```

It is a good point to pause and think why you do not need atomics for `+=` when the map type is `BPF_MAP_TYPE_PERCPU_ARRAY`.

### Expected result (Activity 2)

- `bpftool map dump id <map_id>` shows key `0`.
- Per-CPU `rx_packets` and `rx_bytes` values start at `0`.
- After traffic is generated, per-CPU counters increase.

### Activity 3 — Read and aggregate per-CPU counters from user space

Maps are an easy way to share data between the kernel and user space. For this final task, you will implement a loader/reader that (1) loads the BPF object, (2) attaches the XDP program to the selected interface, (3) finds the map FD for `xdp_stats_map`, and (4) once per second reads key `0` and prints totals.

We provide for you a simple user-space program template that performs steps (1)–(2) for you. You can find it in `xdp_count_user.c`. Your task is to complete step (3) and (4) by implementing a read-and-sum loop.

Because the map is per-CPU, a lookup returns one value per CPU. Your job is to allocate a buffer large enough to hold `n_cpus` copies of `struct datarec`, call `bpf_map_lookup_elem(map_fd, &key, values)`, and then sum the per-CPU values to get total packet and byte counts.

Further reading:

- `libbpf_num_possible_cpus`: [https://libbpf.readthedocs.io/en/latest/api.html](https://libbpf.readthedocs.io/en/latest/api.html)

The core read-and-sum loop looks like this:

```c
int n_cpus = libbpf_num_possible_cpus();
struct datarec values[n_cpus];
__u32 key = 0;

while (running) {
		__u64 packets = 0, bytes = 0;
		if (bpf_map_lookup_elem(map_fd, &key, values) == 0) {
				for (int i = 0; i < n_cpus; i++) {
					packets += values[i].rx_packets;
					bytes   += values[i].rx_bytes;
				}
		}
		printf("packets=%llu bytes=%llu\n", packets, bytes);
		sleep(1);
}
```

As a short written check (2–3 sentences), explain why user space has to do the summation step for per-CPU maps.

Model answer: In a per-CPU map, each CPU maintains its own independent copy of each counter to avoid contention during packet-rate updates. A lookup therefore returns one value per CPU, not one global value. User space must sum those per-CPU values to compute total packets and bytes.

### Activity 4 — Test your implementation

Build the code and load the XDP program, start a mininet topology and load the loopback on host `h1` on interface `h1-eth0`:

```sh
$ make
$ make start
mininet > h1 bpftool prog load xdp_icmp_count_kern.o /sys/fs/bpf/xdp_count
mininet > h1 bpftool prog attach id <prog_id> dev h1-eth0 xdp
``
Alternatively, you can use `xdp-loader` to load and attach in one step:

```sh   
 mininet > h1 xdp-loader load -m skb h1-eth0 xdp_icmp_count_kern.o --prog-name xdp_count_func
```

Attach and start printing counters once per second (generic mode works on most setups, including loopback):

```sh
mininet> h1 ./xdp_count_user --dev h1-eth0 --skb-mode
```

In another terminal, generate traffic:

```sh
mininet > h1 ping -c 5 10.0.0.2
```

You should see `rx_packets` and `rx_bytes` increase.

If you want additional confirmation that things are attached correctly, you can inspect loaded programs and maps with `bpftool` (for example, `sudo bpftool prog show` and `sudo bpftool map show`).

### Expected result (Activity 4)

- The user program prints totals once per second.
- `packets` and `bytes` are non-decreasing.
- Counters increase after `ping` traffic is generated.

## Common failure modes

| Symptom | Likely cause | What to check |
| --- | --- | --- |
| Program fails to load | Verifier rejection or wrong section/program name | Confirm `SEC("xdp")`, program name, and inspect verifier logs via `bpftool prog load ...` |
| `bpf_map_lookup_elem` fails in user space | Wrong map FD or key/value buffer mismatch | Verify map name `xdp_stats_map`, key type `__u32`, and value buffer sized for `n_cpus` |
| Counters stay zero | Program is not attached to the expected interface or mode | Check `xdp-loader status -d <ifname>` and confirm traffic enters that interface |
| Attach fails in native mode | Driver does not support native XDP on this interface | Retry with `--skb-mode` |

## Optional extensions

Once the basic counter works, extend the design by changing the map key. For example, you can count per-protocol (keyed by `__u8 proto`) or per-interface (keyed by `ctx->ingress_ifindex`). Keep the update path verifier-friendly and remember that per-CPU maps require user-space aggregation.


## Debugging eBPF programs

Debugging eBPF programs can be challenging due to the constraints of the eBPF environment and the fact that you cannot use traditional debugging tools. However, there are several techniques and tools you can use to troubleshoot and debug your eBPF programs:

- Use `bpf_printk()`: Prints debug messages from your eBPF program. Messages can be read with:

  ```sh
  sudo cat /sys/kernel/debug/tracing/trace_pipe
  ```

- Use `bpftool`: Inspect loaded programs, map contents, and verifier metadata. You can also use it to load the program directly and see detailed verifier output:

  ```sh
  mininet > h1 bpftool prog load xdp_count_kern.o /sys/fs/bpf/xdp_count
  ```

Further reading:

- `bpftool` man page: [https://man7.org/linux/man-pages/man8/bpftool.8.html](https://man7.org/linux/man-pages/man8/bpftool.8.html)
- libbpf docs: [https://libbpf.readthedocs.io/](https://libbpf.readthedocs.io/)
- eBPF verifier overview: [https://docs.ebpf.io/linux/concepts/verifier/](https://docs.ebpf.io/linux/concepts/verifier/)