# Tutorial 1 - XDP Basics

The programming language for XDP is eBPF (Extended Berkeley Packet Filter) which we will just refer to as BPF. Thus, this tutorial will also be relevant for learning how to write other BPF programs; however, the main focus is on BPF programs that can be used in the XDP-hook. In this and the following couple of activities we will be focusing on the basics to get up and running with BPF; the later lessons will then build on this to teach you how to do packet processing with XDP.

Since this is the first lesson, we will start out softly and include simple tasks. For this first tutorial, focus on being able to build the object file, load it on an interface, and understand what each XDP return code does.

## Compiling and running example code

If you completed the setup dependencies guide, then you should be able to simply run the `$ make` command, in this directory. (The [Makefile](Makefile) and [configure](../configure) script will try to be nice and detect if you didn't complete the setup steps).

We will also use mininet as a way to run our XDP programs, so you can also start the mininet topology with the `make start` command. This will start a simple topology with two hosts and a switch, and you can then load your XDP programs to the interfaces of the hosts and see the effect of your program. This tutorial includes commands executed inside mininet, as well as commands executed in the host OS. The commands executed inside mininet are prefixed with `mininet>`, while the commands executed in the host OS are prefixed with `$`.

## Basic XDP code

The very simple XDP code used in this step is located in
[xdp_pass_kern.c](xdp_pass_kern.c), and displayed below. The starter program already prints a debug message and then returns `XDP_PASS`:

```C
SEC("xdp")
int xdp_prog_simple(struct xdp_md *ctx)
{
    bpf_printk("Hello, XDP! This is a simple XDP program.\n");
    return XDP_PASS;
}
```

## Compiling process

To compile the code, we need a compiler to turn C code into BPF bytecode. There are a number of compilers that can do this, and we use for this task a popular multi-language compiler called LLVM, together with the clang front-end. The clang front-end has a special mode for compiling C code to BPF bytecode, which is enabled by the `-target bpf` flag in the Makefile. The Makefile also includes some additional flags to enable debugging and optimization. The LLVM+clang compiler turns this restricted C code into BPF bytecode and stores it in an ELF object file, named `xdp_pass_kern.o`. ELF is a common file format for executables, object code, shared libraries, and core dumps (we discussed this briefly in the first-year computer architecture module). An ELF file can contain multiple sections, each of which can contain different types of data. In our case, the section named `xdp` contains the BPF bytecode for our XDP program. The section name is defined by the `SEC("xdp")` macro in the code, which tells the compiler to place the BPF bytecode in a section named `xdp` in the ELF file. This is important because when we load the program into the kernel, we need to specify the section name to tell the loader where to find the BPF bytecode. The ELF format is used extensively in Linux and encodes useful details for debugging (for example symbol information and line numbers) and execution (for example memory regions and linked libraries).

### Looking into the BPF-ELF object

You can inspect the contents of the `xdp_pass_kern.o` file with different
tools like `readelf` or `llvm-objdump`. As the Makefile enables the debug
option `-g` (LLVM version >= 4.0), the llvm-objdump tool can annotate
assembler output with the original C code:

Run: `$ llvm-objdump -S xdp_pass_kern.o`

```asm
xdp_pass_kern.o:        file format elf64-bpf

Disassembly of section xdp:

0000000000000000 <xdp_prog_simple>:
;       return XDP_PASS;
       0:       b7 00 00 00 02 00 00 00 r0 = 2
       1:       95 00 00 00 00 00 00 00 exit
```

If you don't want to see the raw BPF instructions add: `--no-show-raw-insn`.
The define/enum XDP_PASS has a value of 2, as can be seen in the dump. The
section name "xdp" was defined by `SEC("xdp")`, and the `xdp_prog_simple:`
is our C-function name.

### Loading and the XDP hook

As you should understand by now, the BPF byte code is stored in an ELF file.  To load this into the kernel, user space needs an ELF loader to read the file and pass it into the kernel in the right format.  The *libbpf* library provides both an ELF loader and several BPF helper functions. It understands BPF Type Format (BTF) and implements [CO-RE](https://nakryiko.com/posts/bpf-core-reference-guide/) relocation as part of ELF loading, which is where our libelf-devel dependency comes from.

The *libxdp* library provides helper functions for loading and installing XDP programs using the XDP multi-dispatch protocol and helper functions for using AF_XDP sockets. The *libxdp* library uses *libbpf* and adds extra features on top.

To load the code to the XDP runtime, you have two options:

* The standard iproute2 tool
* The xdp-loader from xdp-tools

### Loading via iproute2 ip

Iproute2 is a collection of utilities for controlling TCP/IP networking and traffic control in Linux. It includes the `ip` command, which is used for managing network interfaces, routing, and other network-related tasks. We briefly used the ip command to inspect links in thevery first labs. The tool provides out-of-the-box support for libbpf based BPF loading capability that can be used with the standard `ip` tool; so in this case you can actually load our ELF-file `xdp_pass_kern.o` (where we named our ELF section "xdp") like this:

```sh
$ ip link set dev lo xdpgeneric obj xdp_pass_kern.o sec xdp
```

Listing the device via `ip link show` also shows the XDP info:

```sh
$ ip link show dev lo
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 xdpgeneric qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    prog/xdp id 408 name xdp_prog_simple tag 3b185187f1855c4c jited
```

Removing the XDP program again from the device:

```sh
ip link set dev lo xdpgeneric off
```

It is important to note that the `ip` tool from iproute2 does not implement the XDP multi-dispatch protocol. When we use this tool, our program gets attached directly to the `lo` interface.

### Loading using xdp-loader

The xdp-tools project provides the `xdp-loader` tool which has commands for
loading, unloading and showing the status of loaded XDP programs.

We can load our `xdp_pass_kern.o` program and attach it using the XDP
multi-dispatch protocol like this:

```sh
xdp-loader load -m skb lo xdp_pass_kern.o
```

We can show the status of the XDP programs attached to the device:

```sh
$ xdp-loader status lo
CURRENT XDP PROGRAM STATUS:

Interface        Prio  Program name      Mode     ID   Tag               Chain actions
--------------------------------------------------------------------------------------
lo                     xdp_dispatcher    skb      155  90f686eb86991928 
 =>              50     xdp_prog_simple           164  3b185187f1855c4c  XDP_PASS
```

We can unload the program we just added (ID 164 in above example) using this command:

```sh
xdp-loader unload -i 164 lo 
```

Or unload all programs using this command:

```sh
xdp-loader unload -a lo
```

You can list XDP programs  on the device using different commands, and verify
that the program ID is the same:

* `ip link list dev lo`
* `bpftool net list dev lo`
* `xdp-loader status lo`

## Task 1: XDP programming

To bring back now all the material we have learnt as part of this course, you can use your eBPF programs with Mininet. You can load your eBPF programs to the XDP hook of the interfaces of the Mininet hosts, and then send packets to see the effect of your program. For example, you can load the `xdp_pass_kern.o` program to the `h1-eth0` interface of host `h1`, and then ping from `h1` to `h2` to see that the packets are passed through. You can also use `tcpdump` to see the packets on the interface.

For the rest of this exercise, we will bring up the `hello-world` Mininet topology, containing two hosts (h1 and h2) connected to a switch. You can start this topology using the following command:

```bash
$ sudo mn --controller=none --switch=lxbr 
```

you can also use the following `make` command:

```bash
$ make start
```

You can then load the `xdp_pass_kern.o` program to the `h1-eth0` interface of host h1 using the xdp-loader:

```bash
mininet> h1 xdp-loader load -m skb h1-eth0 xdp_pass_kern.o
```

By loading this program, not much will change. Ping will work between hosts h1 and h2 (`mininet> h1 ping h2`), and you can see the packets on the interface using `tcpdump` (`mininet> h1 tcpdump -i h1-eth0`). This is because our program simply returns `XDP_PASS`, which tells the kernel to pass the packet to the normal networking stack for further processing.

Let's now implement a simple XDP program that drops all packets. To do this, add a new XDP program function called `xdp_prog_drop` to [xdp_pass_kern.c](xdp_pass_kern.c). You can use the existing `xdp_prog_simple()` function as a template. The new function should return `XDP_DROP` instead of `XDP_PASS`.

After editing the source file, rebuild the object file:

```bash
make
```

Then, from the Mininet console, unload the current program and load the new one by its program name:

```bash
mininet> h1 xdp-loader unload -a h1-eth0
mininet> h1 xdp-loader load -m skb h1-eth0 xdp_pass_kern.o --prog-name xdp_prog_drop
```

Try now to ping from `h1` to `h2`, and verify that the packets are dropped. You can also use `tcpdump` or Wireshark to observe the packets on the interface. The packets will appear on host `h1`, but host `h2` will not receive them.

## Task 2: XDP tracing

XDP encodes several possible outcomes of packet processing by offering different return values from the XDP program. For example, the `XDP_ABORTED` return value indicates that packet processing was aborted due to an error or exception. When a packet is aborted, it is dropped and does not continue through the normal networking stack. Importantly, `XDP_ABORTED` also triggers the `xdp:xdp_exception` tracepoint, which makes it useful for debugging and tracing.

For this task, implement a second XDP program called `xdp_prog_aborted` in [xdp_pass_kern.c](xdp_pass_kern.c). You can again use the existing `xdp_prog_simple()` function as a template, but this time the function should return `XDP_ABORTED`. You may also keep or add a `bpf_printk()` call if you want an extra debug message in the trace buffer, but the key behavior for this task is returning `XDP_ABORTED` so that the tracepoint fires.

> XDP_ABORTED is different from XDP_DROP, because it triggers the tracepoint named xdp:xdp_exception.

After editing the source file, rebuild and load the aborted program:

```bash
$ make
mininet> h1 xdp-loader unload -a h1-eth0
mininet> h1 xdp-loader load -m skb h1-eth0 xdp_pass_kern.o --prog-name xdp_prog_aborted
```

While pinging from inside the namespace, record this tracepoint and observe these records. E.g with perf like this:

```bash
mininet> h1 perf record -a -e xdp:xdp_exception sleep 4
mininet> h1 perf script
```

In practice, you will need traffic while `perf record` is running. The easiest way is to open a second shell in host `h1` or start the recording in one terminal and generate traffic from another. For example, while the tracepoint is being recorded, run `mininet> h1 ping -c 4 h2`.

The `perf` command is a powerful tool for performance analysis and tracing in Linux. The `record` subcommand is used to record performance data, and the `-a` flag tells it to record system-wide (all CPUs). The `-e` flag specifies the event to record, in this case, the `xdp:xdp_exception` tracepoint. The `sleep 4` command is used to keep the recording running for 4 seconds, allowing you to generate some traffic by pinging from inside the namespace during that time. After recording, you can use the `perf script` command to display the recorded events in a human-readable format. This will show you the details of each XDP exception that occurred during the recording period, including the timestamp, CPU, and any additional information provided by the tracepoint.

Congratulations! You have now successfully written and loaded your first XDP program, and you have also learned how to trace XDP exceptions using perf. This is just the beginning of what you can do with eBPF and XDP, and there are many more advanced features and use cases to explore. In the next exercises, we will dive deeper into the capabilities of eBPF and XDP, and we will learn how to store state in eBPF maps, how to parse packets, and how to implement more complex packet processing logic.
