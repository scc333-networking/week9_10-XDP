# Tutotrial 1 - XDP Basics

The programming language for XDP is eBPF (Extended Berkeley Packet Filter)
which we will just refer to as BPF. Thus, this tutorial will also be
relevant for learning how to write other BPF programs; however, the main
focus is on BPF programs that can be used in the XDP-hook. In this and the
following couple of lessons we will be focusing on the basics to get up and
running with BPF; the later lessons will then build on this to teach you how
to do packet processing with XDP.

Since this is the first lesson, we will start out softly by not actually
including any assignments. Instead, just read the text below and make sure
you can load the program and that you understand what is going on.


## Compiling example code

If you completed the setup dependencies guide, then you should be able to
simply run the `make` command, in this directory. (The [Makefile](Makefile) and
[configure](../configure) script will try to be nice and detect if you didn't complete the
setup steps).

## Simple XDP code

The very simple XDP code used in this step is located in
[xdp_pass_kern.c](xdp_pass_kern.c), and displayed below:

```C
SEC("xdp")
int  xdp_prog_simple(struct xdp_md *ctx)
{
        return XDP_PASS;
}
```

## Compiling process

The LLVM+clang compiler turns this restricted-C code into BPF-byte-code and
stores it in an ELF object file, named `xdp_pass_kern.o`.

### Looking into the BPF-ELF object

You can inspect the contents of the `xdp_pass_kern.o` file with different
tools like `readelf` or `llvm-objdump`. As the Makefile enables the debug
option `-g` (LLVM version >= 4.0), the llvm-objdump tool can annotate
assembler output with the original C code:

Run: `llvm-objdump -S xdp_pass_kern.o`
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

As you should understand by now, the BPF byte code is stored in an ELF file.
To load this into the kernel, user space needs an ELF loader to read the
file and pass it into the kernel in the right format.

The *libbpf* library provides both an ELF loader and several BPF helper
functions. It understands BPF Type Format (BTF) and implements [CO-RE](https://nakryiko.com/posts/bpf-core-reference-guide/)
relocation as part of ELF loading, which is where our libelf-devel
dependency comes from.

The *libxdp* library provides helper functions for loading and installing
XDP programs using the XDP multi-dispatch protocol and helper functions for
using AF_XDP sockets. The *libxdp* library uses *libbpf* and adds extra
features on top. 

To load the code to the XDP runtime, you have two options:

* The standard iproute2 tool
* The xdp-loader from xdp-tools

### Loading via iproute2 ip

Iproute2 provides libbpf based BPF loading capability that can be used with
the standard `ip` tool; so in this case you can actually load our ELF-file
`xdp_pass_kern.o` (where we named our ELF section "xdp") like this:

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
$ ip link set dev lo xdpgeneric off
```

It is important to note that the `ip` tool from iproute2 does not implement
the XDP multi-dispatch protocol. When we use this tool, our program gets
attached directly to the `lo` interface.

### Loading using xdp-loader

The xdp-tools project provides the `xdp-loader` tool which has commands for
loading, unloading and showing the status of loaded XDP programs.

We can load our `xdp_pass_kern.o` program and attach it using the XDP
multi-dispatch protocol like this:

```sh
$ xdp-loader load -m skb lo xdp_pass_kern.o
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