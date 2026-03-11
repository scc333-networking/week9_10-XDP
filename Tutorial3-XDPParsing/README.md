# Tutorial 3 - XDP Parsing + ICMP Rate Limiting

In this activity you will implement safe packet parsing in an XDP/eBPF program and use it to build a simple ICMP rate limiter. This will look a bit like the P4 activity from Week 4. The program will still keep statistics, but instead of only observing traffic it will actively drop ICMP packets that exceed a configured per-source rate.

If you want a quick refresher before you start:

- XDP overview: [https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_XDP/](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_XDP/)
- eBPF concepts (maps, helpers, verifier): [https://ebpf.io/what-is-ebpf/](https://ebpf.io/what-is-ebpf/)

By the end, you should be able to:

- [ ] Explain how BPF maps enable stateful XDP applications (statistics and rate limiting state)
- [ ] Safely parse Ethernet + IPv4 headers inside an XDP program (verifier-friendly)
- [ ] Implement and validate an ICMP rate limiter (PASS vs DROP)

## Exercise — Rate limit ICMP packets

For this exercise, you will implement a simple ICMP rate limiter in XDP. A common reconnaissance pattern is to use ICMP ECHO requests (ping) to discover reachable hosts. To mitigate this, operators often rate limit ICMP traffic. In this tutorial, you will parse incoming packets to identify IPv4 ICMP traffic and apply a per-source rate limit. If a source exceeds the configured limit, packets from that source are dropped; otherwise, they are passed.

This combines concepts from earlier tutorials (parsing + maps) and adds safe concurrent updates for shared state. The tutorial provides starter code and build rules to help you get started:

- Starter code: [xdp_icmp_count_kern.c](xdp_icmp_count_kern.c) use this code to implement your eBPF rate limiter. It contains some helper functions and a skeleton for the XDP program.
- Build rules: [Makefile](Makefile) contains the necessary commands to compile your eBPF program into an object file that can be loaded into the kernel and starting a mininet topology.

## Application Architecture

To implement this functionality, we need per-host kernel state that records:

- how many ICMP packets were seen from a source,
- when the current rate-limit window started.

We also need safe packet parsing and race-safe map updates. Because this state is keyed by source IP, we will use a hash map and protect updates with per-entry locks.

Further reading:

- Hash map type: [https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_HASH/](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_HASH/)
- BPF map types index: [https://docs.ebpf.io/linux/map-type/](https://docs.ebpf.io/linux/map-type/)

### eBPF maps revisited

In the previous tutorial, you used a per-CPU array map for global counters. Here, we need per-source state, so we switch to a hash map. This is an important eBPF design decision: map type affects both correctness and performance.

Quick references:

- `BPF_MAP_TYPE_PERCPU_ARRAY`: [https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_PERCPU_ARRAY/](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_PERCPU_ARRAY/)
- `BPF_MAP_TYPE_HASH`: [https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_HASH/](https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_HASH/)
- Helper docs (`bpf_map_lookup_elem`, `bpf_map_update_elem`): [https://docs.ebpf.io/linux/helper-function/](https://docs.ebpf.io/linux/helper-function/)

As a recap, a **BPF map** is a kernel-managed key/value store that the eBPF program updates and user space can read (and sometimes write). Your XDP program runs once per packet, so statistics usually mean counters such as packets, bytes, drops, redirects, and errors. XDP runs in parallel across CPUs, so coherent shared state requires concurrency-safe design.

- use **atomic operations** on shared counters (can reduce performance under contention), or
- use a **per-CPU map** (each CPU has its own copy and user space aggregates).

In the previous tutorial, you explored the latter scenario. In this exercise we use a hash map and protect per-key updates with a spin lock in the map value (`icmp_rl_map`). Unlike arrays, which require a compact integer key space, source IPs are effectively unbounded, so hash maps are a natural fit:

- **Key**: `__u32` IPv4 source address (`ip->saddr`, in network byte order)
- **Value**: a small struct holding the current window start time and packet count
- **Lookup/update**: on each packet, look up the source IP and update that entry

In code, this looks like:

- [`bpf_map_lookup_elem(&icmp_rl_map, &src_ip)`](https://docs.ebpf.io/linux/helper-function/bpf_map_lookup_elem/) to find the per-source record
- If missing, initialize it with [`bpf_map_update_elem(&icmp_rl_map, &src_ip, &init, BPF_ANY)`](https://docs.ebpf.io/linux/helper-function/bpf_map_update_elem/)

### Synchronizing access

Your XDP program runs in parallel on multiple CPUs. Two packets from the same source (same map key) can be processed concurrently, so a naive update like `st->count += 1;` can lose increments due to data races. To make per-source updates race-safe, this tutorial uses a **spin lock inside the map value**. This is a common pattern for synchronizing access to shared state in eBPF programs. The idea is to include a `struct bpf_spin_lock` in the value struct of the map (e.g, `struct rl_state { struct bpf_spin_lock lock; ... }`), and then use [`bpf_spin_lock()`](https://docs.ebpf.io/linux/helper-function/bpf_spin_lock/) and [`bpf_spin_unlock()`](https://docs.ebpf.io/linux/helper-function/bpf_spin_unlock/) around the critical section that updates the state. Per-record locking (a lock per key) scales much better than a single global lock, because different source IPs can be updated in parallel.

Further reading on concurrency in eBPF:

- Spin locks concept + constraints: [https://docs.ebpf.io/linux/concepts/concurrency/](https://docs.ebpf.io/linux/concepts/concurrency/)
- `bpf_spin_lock` helper: [https://docs.ebpf.io/linux/helper-function/bpf_spin_lock/](https://docs.ebpf.io/linux/helper-function/bpf_spin_lock/)

Important constraints to remember:

- **No helper calls while holding the lock**. The verifier will reject programs that call helpers (including `bpf_printk()`) inside the locked region.

### Safe parsing in XDP

Building on the last two tutorials, we will explore in this final tutorial how to safely parse packet headers in XDP. The eBPF verifier enforces strict rules to ensure that your program will never read out-of-bounds memory, which is crucial for security and stability. This means that every time you access packet data, you must first check that the relevant header is fully contained within the bounds of the packet. In XDP, packet data is accessed via two pointers in the context structure:

- `ctx->data` (start of packet)
- `ctx->data_end` (end of packet)

The verifier requires you to prove you never read past `data_end`. That means **every** header access needs a bounds check, and variable-length headers (like IPv4 with `ihl`) require extra validation. If the verifier cannot prove safety, the kernel rejects the program at load time.

Further reading:

- Verifier basics: [https://docs.ebpf.io/linux/concepts/verifier/](https://docs.ebpf.io/linux/concepts/verifier/)

A minimal IPv4 parsing pipeline is similar to the P4 parser block, but you need to include some explicit code to convert field into values. Here is a simple break down of the steps to parse Ethernet + IPv4 headers in XDP:

1. Parse `struct ethhdr` and verify it is fully in-bounds ()
2. Check `eth->h_proto == ETH_P_IP`
3. Parse `struct iphdr` and verify:
   - the fixed header is in-bounds
   - `ip->ihl >= 5`
   - the full header (`ip->ihl * 4`) is in-bounds
4. Check `ip->protocol == IPPROTO_ICMP`

To help your development effort, you can use the inline functions in [`common/parsing_helpers.h`](../common/parsing_helpers.h) to perform these checks and parsing steps. These helpers are verifier-friendly and return `NULL` when a header is not fully in bounds.

### Program logic

Implement or complete the code so that:

1. Define a struct for the rate limit state (e.g., `struct rl_state { struct bpf_spin_lock lock; __u64 window_start; __u32 count; }`). You can use ideas from week 14 tutorial to design your state struct. Your struct should include a spin lock for concurrency control, a timestamp for the start of the current window, and a counter for the number of packets in the current window.
2. Use a hash map to store the rate limit state per source IP. The key should be the source IPv4 address, and the value should be your `rl_state` struct. You can define this map in your eBPF program using the appropriate BPF map definition syntax.
3. The program must safely parse Ethernet + IPv4 headers and detect **IPv4 ICMP** packets. You can use the helper functions in `parsing_helpers.h` to perform these checks and parsing steps.
4. For each detected ICMP packet, look up the source IP in the hash map to retrieve the current rate limit state. If there is no existing entry for that source IP, initialize a new one with the current timestamp and a count of 1. If there is an existing entry, check if the current time is within the same window (e.g., 1 second) as the `window_start`. If it is, increment the count; if it is not, reset the `window_start` to the current time and reset the count to 1. Use the spin lock to protect updates to the rate limit state for that source IP.
5. When a source exceeds the limit, return `XDP_DROP`; otherwise return `XDP_PASS`.

We provide preprocessor definitions for the default limit in the kernel program: `ICMP_PPS_LIMIT` and `WINDOW_NS` (1 second = $10^9$ ns).

### Expected behavior checklist

After implementing the logic, you should observe:

- Non-ICMP and non-IPv4 traffic is passed.
- ICMP traffic below the threshold is passed.
- ICMP traffic above the threshold is dropped.
- Counters and map entries change as traffic is generated.

## Testing your implementation

You can build and test your implementation using the provided Makefile and the `xdp-loader` or `bpftool` tools. To compile your eBPF program and produce an eBPF object file (`*.o`), simply run in the Tutorial directory:

```sh
make
```

Start the mininet topology using the provided Makefile rule:

```sh
make start
```

Attach the program to `h1-eth0` in SKB/generic mode (works in most environments):

```sh
$ make
mininet > h1 xdp-loader unload -a h1-eth0 || true
mininet > h1 xdp-loader load -m skb -n xdp_icmp_ratelimit h1-eth0 xdp_icmp_count_kern.o
mininet > h1 xdp-loader status h1-eth0
```

Generate ICMP traffic below the limit:

```sh
mininet > h1 ping -c 5 -i .1 h2 # Generate 5 pings with 150ms interval (below the default limit of 5 pps)
```

If your code works correctly, some packets should be dropped.

To generate traffic above the default limit, try a faster ping interval:

```sh
mininet > h1 ping -c 20 -i 0.02 h2
```

### Debugging your eBPF program

To find the map ID (look for `icmp_rl_map`) and inspect contents, use:

```sh
mininet > h1 bpftool map show | grep icmp_rl_map
mininet > h1 bpftool map dump id <MAP_ID>
```

You can also inspect loaded programs and verifier-related metadata:

```sh
mininet > h1 bpftool prog show
```

## Debugging eBPF programs

Debugging eBPF programs can be challenging due to the constraints of the eBPF environment and the fact that you cannot use traditional debugging tools. However, there are several techniques and tools you can use to troubleshoot and debug your eBPF programs:

- Use `bpf_printk()`: This function allows you to print debug messages from your eBPF program. You can use it to log variable values, execution flow, and other relevant information. The messages can be viewed through the file `/sys/kernel/debug/tracing/trace_pipe` (i.e., `$s cat /sys/kernel/debug/tracing/trace_pipe`)
- Use `bpftool`: This tool provides commands to inspect and interact with eBPF programs and maps. You can use it to check whether your program is loaded, view map contents, and inspect metadata.

Further reading:

- `bpftool` man page: [https://man7.org/linux/man-pages/man8/bpftool.8.html](https://man7.org/linux/man-pages/man8/bpftool.8.html)
- libbpf docs: [https://libbpf.readthedocs.io/](https://libbpf.readthedocs.io/)
