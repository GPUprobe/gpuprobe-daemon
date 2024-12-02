CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := x86

CFLAGS := -O2 -g --target=bpf -Wno-compare-distinct-pointer-types
CFLAGS += -D__TARGET_ARCH_$(ARCH)
INCLUDES := -Iinclude -I. -I../../../libbpf/src/root/usr/include

all: gpuprobe.bpf.o gpuprobe.skel.h

%.bpf.o: %.bpf.c vmlinux.h
	@$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@

gpuprobe.skel.h: gpuprobe.bpf.o
	@$(BPFTOOL) gen skeleton gpuprobe.bpf.o name gpuprobe > gpuprobe.skel.h

vmlinux.h:
	@$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# .PHONY: clean
clean:
	@rm -rf *.bpf.o *.skel.h
