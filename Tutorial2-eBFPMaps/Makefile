# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS := xdp_count_kern
USER_TARGETS := xdp_count_user

LLC ?= llc
CLANG ?= clang
CC := gcc

COMMON_DIR := ../common
COMMON_OBJS := $(COMMON_DIR)/common_user_bpf_xdp.o

include $(COMMON_DIR)/common.mk

start:
	mn --controller none --switch lxbr -i 192.168.0.0/16 --arp --mac
