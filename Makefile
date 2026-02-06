CC ?= cc
CFLAGS ?= -O2 -g -Wall -Wextra -Wshadow -Wformat=2 -Wundef -Wpointer-arith -Wcast-qual -Wstrict-prototypes -std=c11
<<<<<<< HEAD
CPPFLAGS ?= -Iinclude
LDFLAGS ?=
LDLIBS ?=

=======
CPPFLAGS ?= -Iinclude -Ibpf
LDFLAGS ?=
LDLIBS ?=

# ===== eBPF toolchain =====
CLANG ?= clang
BPFOOL ?= bpftool

BPF_CFLAGS ?= -O2 -g -target bpf -D__TARGET_ARCH_x86
BPF_CFLAGS += -Iinclude -Ibpf -I.

VMLINUX_H := include/vmlinux.h

BPF_SRCS := \
	bpf/xtop_softirq.bpf.c \
	bpf/xtop_runqlat.bpf.c

BPF_OBJS := $(BPF_SRCS:.bpf.c=.bpf.o)
BPF_SKELS := $(BPF_SRCS:.bpf.c=.skel.h)

# ===== user-space =====
>>>>>>> 6e7074a (ebpf 초기 코드)
BIN := xtop
SRCS := \
	src/main.c \
	src/proc_stat.c \
	src/proc_mem.c \
	src/proc_proc.c \
<<<<<<< HEAD
	src/fmt.c

OBJS := $(SRCS:.c=.o)

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)
=======
	src/fmt.c \
	src/bpf.c

OBJS := $(SRCS:.c=.o)

.PHONY: all clean bpf

all: $(BIN)

# libbpf deps
LDLIBS += -lbpf -lelf -lz

$(BIN): $(BPF_SKELS) $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)
>>>>>>> 6e7074a (ebpf 초기 코드)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

<<<<<<< HEAD
clean:
	rm -f $(BIN) $(OBJS)
=======
# ===== eBPF build rules =====
bpf: $(BPF_SKELS)

src/bpf.o: $(BPF_SKELS)

$(VMLINUX_H):
	@mkdir -p include
	$(BPFOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

bpf/%.bpf.o: bpf/%.bpf.c $(VMLINUX_H) include/xtop_bpf.h
	$(CLANG) $(BPF_CFLAGS) -c -o $@ $<

bpf/%.skel.h: bpf/%.bpf.o
	$(BPFOOL) gen skeleton $< > $@

clean:
	rm -f $(BIN) $(OBJS) $(BPF_OBJS) $(BPF_SKELS) $(VMLINUX_H)
>>>>>>> 6e7074a (ebpf 초기 코드)
