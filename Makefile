# Makefile
BPF_CLANG ?= clang
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 -I./bpf -I./include
CFLAGS := -O2 -g -Wall -Wextra -I./include -I./src
LDLIBS := -lbpf -lelf -lz

VMLINUX := bpf/vmlinux.h
BPF_OBJ := bpf/xtop.bpf.o
SKEL_H := src/xtop.skel.h

.PHONY: all clean vmlinux

all: xtop

vmlinux:
	@if [ ! -f "$(VMLINUX)" ]; then \
	  echo "[+] generating $(VMLINUX)"; \
	  bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX); \
	else \
	  echo "[=] $(VMLINUX) exists"; \
	fi

$(BPF_OBJ): vmlinux bpf/xtop.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c bpf/xtop.bpf.c -o $(BPF_OBJ)

$(SKEL_H): $(BPF_OBJ)
	bpftool gen skeleton $(BPF_OBJ) > $(SKEL_H)

xtop: $(SKEL_H) src/xtop.c include/xtop.h
	$(CC) $(CFLAGS) -o $@ src/xtop.c $(LDLIBS)

clean:
	rm -f xtop $(BPF_OBJ) $(SKEL_H)
