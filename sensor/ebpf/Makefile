BPFTOOL ?= bpftool
CLANG ?= clang
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
TARGET_ARCH ?= x86
MULTIARCH ?= $(shell uname -m)-linux-gnu
BPF_CFLAGS ?= -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_$(TARGET_ARCH) -I. -I/usr/include/$(MULTIARCH)

.DELETE_ON_ERROR:

.PHONY: all clean

all: runtime.bpf.o

vmlinux.h:
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > vmlinux.h.tmp
	mv vmlinux.h.tmp vmlinux.h

runtime.bpf.o: runtime.bpf.c runtime.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c runtime.bpf.c -o runtime.bpf.o

clean:
	rm -f runtime.bpf.o vmlinux.h vmlinux.h.tmp
