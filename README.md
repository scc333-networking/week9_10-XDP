# SCC.333 (Week 9-10) - Introduction to eBPF and XDP

The Linux kernel has evolved to include powerful features for monitoring and controlling system behavior. Two of these features are eBPF (extended Berkeley Packet Filter) and XDP (eXpress Data Path). This lab exercise will introduce you to these technologies, allowing you to understand their capabilities and how they can be used for network performance monitoring and security.

By the end of this lab activity you will be able to:

* [ ] Understand the basics of eBPF and XDP
* [ ] Write simple eBPF programs to monitor network traffic
* [ ] Use XDP to improve network performance
* [ ] Analyze the performance benefits of using eBPF and XDP in a real-world scenario

The material for this lab is based on the [XDP tutorial](https://github.com/xdp-project/xdp-tutorial), which provides a comprehensive introduction to these technologies, along with practical examples and exercises to help you get hands-on experience.

## Initial setup

Before starting the exercises, make sure you build the libraries for the labs using the following command:

```
./configure
make
```

These commands will build the necessary libraries and tools for the exercises. If you encounter any issues during the setup, please let us know so we can assist you in getting everything up and running smoothly.

## What is eBPF?

eBPF (extended Berkeley Packet Filter) is a powerful technology in the Linux kernel that allows you to run sandboxed programs in the kernel space. These programs can be used for a variety of purposes, including network monitoring, performance analysis, and security enforcement. eBPF programs are safe to run in the kernel because they are verified before execution, ensuring they do not crash the system or perform unsafe operations.


Berkley Packet Filter (BPF) was originally designed for packet filtering in network applications. One of the initial application of BPF was in the `tcpdump` tool (an early command line version of Wireshark), which uses BPF to capture and filter network packets efficiently. eBPF extends the capabilities of BPF, allowing for more complex and versatile programs that can be attached to various kernel hooks, such as system calls, tracepoints, and network events. 

eBPF programs can be written in several languages, including C and Python, and are compiled into bytecode that the kernel can execute. Nonetheless, developers have several restrictions when writing eBPF programs, such as limited loops and no direct access to kernel memory, to ensure safety and performance. Writting eBPF programs resembles your experience with P4 programming, as both involve writing code that runs in a constrained environment with specific APIs and limitations. Each language has a specific compiler that translates the code into eBPF bytecode, which is then loaded into the kernel and executed in response to specific events or conditions. For example, C code can be compiled to eBPF bytecode using the LLVM compiler with the clang front-end, while Python code can be compiled using libraries such as BCC (BPF Compiler Collection) or BPFd (BPF Daemon). The choice of language and compiler depends on the specific use case and the developer's preferences. The compiler output an object file containing eBPF bytecode. 

eBPF bytecode is an architecture-independent ISA (register-based, 64-bit, R0–R10, etc.) that the kernel verifies and then either interprets or JIT-compiles into the host CPU’s native machine code (x86-64, arm64, etc.). This allows eBPF programs to run efficiently in the kernel, providing high performance for tasks such as packet processing and system monitoring. The Linux kernel offers hooks to attach eBPF programs to various stages of the network stack, allowing you to monitor and manipulate network traffic at different points in the processing pipeline. eBPF has a wide range of applications, including: 

* Network performance monitoring: eBPF can be used to collect detailed metrics about network traffic, such as latency, throughput, and packet drops, without the overhead of traditional monitoring tools.
* Security enforcement: eBPF can be used to implement security policies, such as blocking malicious traffic or detecting anomalies in network behavior.
* Performance analysis: eBPF can be used to analyze system performance by tracing system calls, monitoring resource usage, and identifying bottlenecks in applications. 

It is pretty common to use eBPF programs to attach to OS events, such as system calls or tracepoints, to gather insights about the system's behavior. For example, you can write an eBPF program that attaches to the `open` system call to monitor file access patterns, or to a tracepoint in the network stack to analyze packet processing. Similarly, the Linux kernel offers hooks to attach eBPF programs to various stages of the network stack, allowing you to monitor and manipulate network traffic at different points in the processing pipeline.

If you want to learn more about eBPF applications, you can read the [eBPF community page](https://ebpf.io/), which provides a wealth of information and resources about eBPF, including tutorials, documentation, and examples of real-world use cases.

## What is XDP?

XDP (eXpress Data Path) is a high-performance packet processing framework in the Linux kernel. It lets you run a small program very early in the receive (RX) path—typically right in the network driver—so you can decide what to do with each packet before the normal networking stack (IP routing, netfilter/iptables, sockets, etc.) gets involved. You can imagine this as a function that you can register with the OS and execute code for each packer recieved by the OS. XDP is a type of kernel hook that allows you to attach eBPF programs directly to the network driver, and the code should be compiled into eBPF bytecode. 

In this set of lab tutorial, we will use XDP to attach eBPF programs to a network device and process packets. We will try to perform a comparative analysis between P4 and eBPF and explore commonalities as well as differences. By the way, some high-end network cards (e.g. from Intel) support offloading XDP programs to the NIC hardware, which can further improve performance by allowing packet processing to be done directly on the network card, reducing latency and CPU overhead. Similar to P4 programs, certain NIC cards can execute XDP programs on the NIC hardware. 

A key motivation for supporting XDP in the Linux kernel is to enable high-performance custom packet processing. The network stack in the Linux kernel is designed to be flexible and support a wide range of use cases, but this flexibility can come at the cost of performance. By allowing developers to write custom eBPF programs that can be executed directly in the network driver, XDP provides a way to achieve high performance for specific packet processing tasks, such as filtering, load balancing, or DDoS mitigation. eBPF programs for example are used by Cillium, a popular open-source networking and security solution for Kubernetes, to implement high-performance network policies and load balancing.

## Lab structure

To better understand eBPF and XDP, we will go through a series of exercises that will guide you through the process of writing and deploying eBPF programs, as well as using XDP to enhance network performance. Each exercise will build upon the previous one, allowing you to gradually develop your skills and knowledge in these technologies. As par of this activity we offer the following exercises:

* [XDP basics](./Tutorial1-XDPbasics/README.md): In this exercise, you will learn the basics of XDP and how to write a simple eBPF program to process network packets.


## Further reading

* [eBPF documentation](https://ebpf.io/docs/): The official documentation for eBPF, which provides detailed information about the technology, its features, and how to use it effectively.
* [XDP documentation](https://ebpf.io/docs/xdp/): The official documentation for XDP, which provides information about how to use XDP for high-performance packet processing, including examples and best practices.
* [Cillium](https://cilium.io/): An open-source networking and security solution for Kubernetes that uses eBPF to implement high-performance network policies and load balancing. The Cillium documentation provides insights into how eBPF is used in real-world applications and can serve as a valuable resource for learning about eBPF and XDP in practice.
