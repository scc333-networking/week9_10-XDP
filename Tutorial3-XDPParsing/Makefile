# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS := xdp_icmp_count_kern

LLC ?= llc
CLANG ?= clang
CC := gcc

COMMON_DIR := ../common
COMMON_OBJS := $(COMMON_DIR)/common_user_bpf_xdp.o

include $(COMMON_DIR)/common.mk

start:
	sysctl -w net.bridge.bridge-nf-call-ip6tables=0
	sysctl -w net.bridge.bridge-nf-call-iptables=0
	sysctl -w net.bridge.bridge-nf-call-arptables=0
	mn --controller none --switch lxbr --arp --mac
