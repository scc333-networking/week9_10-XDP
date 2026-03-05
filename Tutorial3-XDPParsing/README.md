# Tutorial 3 - XDP Parsing + ICMP Rate Limiting

In this activity you will implement a safe packet parsing mechanism in an XDP/eBPF program and use it to build a simple rate-limiting application for ICMP. This will look a bit like the P4 activity we did back in Week 4. The program will still keep statistics, but instead of only observing traffic it will actively drop ICMP packets that exceed a configured per-source rate.

By the end, you should be able to:

- [ ] Explain how BPF maps enable stateful XDP applications (statistics and rate limiting state)
- [ ] Safely parse Ethernet + IPv4 headers inside an XDP program (verifier-friendly)
- [ ] Implement and validate an ICMP rate limiter (PASS vs DROP)

## Exercise — Rate limit ICMP packets

For this exercise, you will implement a simple ICMP rate limiter in XDP. It is common for network attackers that have gained acccess to a production to use ICMP ECHO packets (ping) to probe the network and discover online hosts. To mitigate such attacks, network administrators often implement rate limiting for ICMP messages. To replicate this functionality using eBPF packet, we will implement a program that parses incoming packets to identify IPv4 ICMP traffic, and then apply a per-source rate limit. If a source exceeds the configured limit, the program will drop packets from that source; otherwise, it will pass them. This will blend some of the concepts from the previous tutorials (parsing, maps) and add a bit of concurrency control for the rate limiter state. The tutorial offers the following starter code and build rules to help you get started:

- Starter code: [xdp_icmp_count_kern.c](xdp_icmp_count_kern.c) use this code to implement your eBPF rate limiter. It contains some helper functions and a skeleton for the XDP program.
- Build rules: [Makefile](Makefile) contains the necessary commands to compile your eBPF program into an object file that can be loaded into the kernel and starting a mininet topology.

## Application Architecture

In order to realise this functionality, we will need to maintain state in the kernel per hosts, to record the number of ICMP packets received from each source and the time of the first packet in the current window, and explore how packet parsing works in eBPF. Furthermore, because the state will use a lookup structure, we will also explore the different types of BPF maps, as well as, how we can coordinate access to share data structures in the kernel, without race conditions. Lets discuss each of these key components.

The repo contains a canonical “per-action counter” helper that uses a per-CPU array map:

* Kernel-side helper: [common/xdp_stats_kern.h](../common/xdp_stats_kern.h)
* Shared value struct: [common/xdp_stats_kern_user.h](../common/xdp_stats_kern_user.h)

### eBPF maps revisited

In the previous tutorial, we used per CPU array maps to maintain global counters for packets and bytes. In this tutorial, we will need to maintain more complex state (per-source rate limit state), which requires a different map type (hash map). This highlights an important aspect of eBPF programming: the choice of map type is crucial for both correctness and performance. XDP provides a variety of map types, each with its own characteristics and use cases. For example, array maps are simple and efficient for small, fixed-size data, while hash maps are more flexible for dynamic key-value pairs. In our case, since we need to track state per source IP address, a hash map is the appropriate choice. You can read more about the different map types and their use cases in the official eBPF documentation: [https://docs.ebpf.io/linux/map-type/](https://docs.ebpf.io/linux/map-type/).

As a recap, an **BPF map** is a kernel-managed key/value store that both the eBPF program (kernel side) can update, and user space can read (and sometimes write). Your XDP program runs once per packet, so “statistics” typically mean counters like, packets, bytes, drops, redirects, errors, etc. Your computer is usually a big parallel machine, and XDP runs in parallel across CPUs. Maintaining coherent state across these parallel executions is challenging. If two CPUs update the same state at the same time, you can lose updates unless you design for concurrency.

* use **atomic operations** on shared counters, which though can slow down your code due to locking, or
* use a **per-CPU map** (each CPU has its own counter, user space sums them).

In the previous tutorial, we explore the later scenario. In this tutorial’s exercise we will use a hash map, together with a list of spin locks to protect concurrent updates in the structure `icmp_rl_map`. The hash map uses source IPv4 address as the key, storing the rate limit state (updated under a BPF spin lock). Unlike arrays, that require a small integer key-space, source IPs are essentially unbounded, so a hash map is the right primitive. A hash map is a natural fit:

- **Key**: `__u32` IPv4 source address (`ip->saddr`, in network byte order)
- **Value**: a small struct holding the current window start time and packet count
- **Lookup/update**: on each packet, look up the source IP and update that entry

In code, this looks like:

- [`bpf_map_lookup_elem(&icmp_rl_map, &src_ip)`](https://docs.ebpf.io/linux/helper-function/bpf_map_lookup_elem/) to find the per-source record
- If missing, initialize it with [`bpf_map_update_elem(&icmp_rl_map, &src_ip, &init, BPF_ANY)`](https://docs.ebpf.io/linux/helper-function/bpf_map_update_elem/)


### Synchronizing access

Your XDP program runs in parallel on multiple CPUs. Two packets from the same source (same map key) can be processed concurrently, so a naive update like `st->count += 1;` can lose increments due to data races. To make per-source updates race-safe, this tutorial uses a **spin lock inside the map value**. This is a common pattern for synchronizing access to shared state in eBPF programs. The idea is to include a `struct bpf_spin_lock` in the value struct of the map (e.g, `struct rl_state { struct bpf_spin_lock lock; ... }`), and then use [`bpf_spin_lock()`](https://docs.ebpf.io/linux/helper-function/bpf_spin_lock/) and [`bpf_spin_unlock()`](https://docs.ebpf.io/linux/helper-function/bpf_spin_unlock/) around the critical section that updates the state. Per-record locking (a lock per key) scales much better than a single global lock, because different source IPs can be updated in parallel.

Important constraints to remember:

- **BTF is required** for maps whose values contain `struct bpf_spin_lock`. In practice, compile your BPF object with debug info (commonly `clang ... -g ...`) so the object contains a `.BTF` section.
- **No helper calls while holding the lock**. The verifier will reject programs that call helpers (including `bpf_printk()`) inside the locked region.

### Safe parsing in XDP

Building on the last two tutorials, we will explore in this final tutorial how to safely parse packet headers in XDP. The eBPF verifier enforces strict rules to ensure that your program will never read out-of-bounds memory, which is crucial for security and stability. This means that every time you access packet data, you must first check that the relevant header is fully contained within the bounds of the packet. In XDP, packet data is accessed via two pointers in the context structure:

- `ctx->data` (start of packet)
- `ctx->data_end` (end of packet)

The verifier requires you to prove you will never read past `data_end`. That means that **every** header access must be preceded by a bounds check, as well as that variable-length headers (like IPv4 with `ihl`) require extra care. If the kernel detects that the program might read out-of-bounds, it will reject the program at load time and you will have to fix the code before you can run it.

A minimal IPv4 parsing pipeline is similar to the P4 parser block, but you need to include some explicit code to convert field into values. Here is a simple break down of the steps to parse Ethernet + IPv4 headers in XDP:

1. Parse `struct ethhdr` and verify it is fully in-bounds ()
2. Check `eth->h_proto == ETH_P_IP`
3. Parse `struct iphdr` and verify:
	 - the fixed header is in-bounds
	 - `ip->ihl >= 5`
	 - the full header (`ip->ihl * 4`) is in-bounds
4. Check `ip->protocol == IPPROTO_ICMP`

To help your development effort, you can use the inline functions in [`common/xdp_parsing_helpers.h`](../common/xdp_parsing_helpers.h) to perform these checks and parsing steps. These functions are designed to be verifier-friendly and will return `NULL` if the header is not fully in-bounds, allowing you to handle errors gracefully.

### Program logic

Understand and (if asked) modify the code so that:

1. Define a struct for the rate limit state (e.g., `struct rl_state { struct bpf_spin_lock lock; __u64 window_start; __u32 count; }`). You can use ideas from week 14 tutorial to design your state struct. Your struct should include a spin lock for concurrency control, a timestamp for the start of the current window, and a counter for the number of packets in the current window.
2. Use a hash map to store the rate limit state per source IP. The key should be the source IPv4 address, and the value should be your `rl_state` struct. You can define this map in your eBPF program using the appropriate BPF map definition syntax.
3. The program must safely parse Ethernet + IPv4 headers and detect **IPv4 ICMP** packets. You can use the helper functions in `xdp_parsing_helpers.h` to perform these checks and parsing steps. 
4. For each detected ICMP packet, look up the source IP in the hash map to retrieve the current rate limit state. If there is no existing entry for that source IP, initialize a new one with the current timestamp and a count of 1. If there is an existing entry, check if the current time is within the same window (e.g., 1 second) as the `window_start`. If it is, increment the count; if it is not, reset the `window_start` to the current time and reset the count to 1. Use the spin lock to protect updates to the rate limit state for that source IP.
5. When a source exceeds the rate, packets are dropped (`XDP_DROP`); otherwise they are passed (`XDP_PASS`).

We provide some pre-processor definitions for the default limit, which is defined in the kernel program as `ICMP_PPS_LIMIT` and the monitoring interval as `WINDOWS_NS`, set to $10^9$ nsec or 1 second.

## Testing your implementation

You can build and test your implementation using the provided Makefile and the `xdp-loader` or `bpftool` tools. To compile your eBPF program and produce an eBPF object file (`*.o`), simply run in the Tutorial directory:

```sh
$ make
```

Start the mininet topology using the provided Makefile rule:

```sh
$ make start 
```

Attach the program to `lo` in SKB/generic mode (works in most environments):

```sh
mininet > h1 xdp-loader unload -a h1-eth0 || true
mininet > h1 xdp-loader load -m skb -n xdp_icmp_ratelimit h1-eth0 xdp_icmp_count_kern.o
mininet > h1 xdp-loader status h1-eth0
```

Generate ICMP traffic below the limit:

```sh
mininet > h1 ping -c 5 -i .1 h2 # Generate 5 pings with 150ms interval (below the default limit of 5 pps)
```

If your code works correctly, some packets should be dropped.

### Debugging your eBPF program

In order to  find the map ID (look for `icmp_rl_map`) and use the map dump command to inspect ct the contents of the map. If your map is not used by your program, the map entry will not appear in the list. you can use the following commands:

```sh
sudo bpftool map show | grep icmp_rl_map
sudo bpftool map dump id <MAP_ID>
```

## Debugging eBPF programs

Debugging eBPF programs can be challenging due to the constraints of the eBPF environment and the fact that you cannot use traditional debugging tools. However, there are several techniques and tools you can use to troubleshoot and debug your eBPF programs:

* Use `bpf_printk()`: This function allows you to print debug messages from your eBPF program. You can use it to log variable values, execution flow, and other relevant information. The messages can be viewed through the file `/sys/kernel/debug/tracing/trace_pipe` (i.e., `$s cat /sys/kernel/debug/tracing/trace_pipe`)
* Use `bpftool`: This tool provides various commands to inspect and interact with eBPF programs and maps. You can use it to check if your program is loaded, view map contents, and monitor program execution. To load the program you can use alternatively the command `mininet > h1 bpftool prog load xdp_icmp_count_kern.o /sys/fs/bpf/xdp_count ` to load the program and received detailed information about the verification process. The output of the program can help you identify issues with your code and understand how the verifier is interpreting it.
