// bpf/xtop.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define RQ_BUCKETS 9
#define SOFTIRQ_VECS 10


// /sys/kernel/tracing/events/sched/sched_wakeup/format
struct sched_wakeup_ctx {
    __u64 __common;     // common_type/u8/u8/common_pid (8 bytes)
    char comm[16];
    __s32 pid;
    __s32 prio;
    __s32 success;
    __s32 target_cpu;
};

// /sys/kernel/tracing/events/sched/sched_switch/format
struct sched_switch_ctx {
    __u64 __common;     // 8 bytes common
    char prev_comm[16];
    __s32 prev_pid;
    __s32 prev_prio;
    __s64 prev_state;   // "long" on 64-bit kernels -> 8 bytes
    char next_comm[16];
    __s32 next_pid;
    __s32 next_prio;
};

// /sys/kernel/tracing/events/irq/softirq_entry|exit/format
struct softirq_ctx {
    __u64 __common;     // 8 bytes common
    __u32 vec;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, __u32);     // pid
    __type(value, __u64);   // wakeup timestamp ns
} wakeup_ts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, RQ_BUCKETS);
    __type(key, __u32);
    __type(value, __u64);   // count
} rq_hist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, SOFTIRQ_VECS);
    __type(key, __u32);
    __type(value, __u64);   // start ns
} softirq_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, SOFTIRQ_VECS);
    __type(key, __u32);
    __type(value, __u64);   // accumulated ns
} softirq_time SEC(".maps");

static __always_inline __u32 rq_bucket_idx(__u64 delta_us)
{
    if (delta_us < 1)   return 0;
    if (delta_us < 2)   return 1;
    if (delta_us < 4)   return 2;
    if (delta_us < 8)   return 3;
    if (delta_us < 16)  return 4;
    if (delta_us < 32)  return 5;
    if (delta_us < 64)  return 6;
    if (delta_us < 128) return 7;
    return 8;
}

SEC("tracepoint/sched/sched_wakeup")
int tp_sched_wakeup(struct sched_wakeup_ctx *ctx)
{
    __u32 pid = (__u32)ctx->pid;
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&wakeup_ts, &pid, &now, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_switch")
int tp_sched_switch(struct sched_switch_ctx *ctx)
{
    __u32 next_pid = (__u32)ctx->next_pid;

    __u64 *tsp = bpf_map_lookup_elem(&wakeup_ts, &next_pid);
    if (!tsp)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 delta_us = (now - *tsp) / 1000;

    __u32 idx = rq_bucket_idx(delta_us);
    __u64 *cnt = bpf_map_lookup_elem(&rq_hist, &idx);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);

    bpf_map_delete_elem(&wakeup_ts, &next_pid);
    return 0;
}

SEC("tracepoint/irq/softirq_entry")
int tp_softirq_entry(struct softirq_ctx *ctx)
{
    __u32 vec = ctx->vec;
    if (vec >= SOFTIRQ_VECS) return 0;

    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&softirq_start, &vec, &now, BPF_ANY);
    return 0;
}

SEC("tracepoint/irq/softirq_exit")
int tp_softirq_exit(struct softirq_ctx *ctx)
{
    __u32 vec = ctx->vec;
    if (vec >= SOFTIRQ_VECS) return 0;

    __u64 *startp = bpf_map_lookup_elem(&softirq_start, &vec);
    if (!startp || *startp == 0) return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 delta = now - *startp;

    __u64 *acc = bpf_map_lookup_elem(&softirq_time, &vec);
    if (acc)
        __sync_fetch_and_add(acc, delta);

    __u64 zero = 0;
    bpf_map_update_elem(&softirq_start, &vec, &zero, BPF_ANY);
    return 0;
}
