#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "xtop_bpf.h"

char LICENSE[] SEC("license") = "GPL";

struct tp_sched_wakeup {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;

    char  comm[16];
    __s32 pid;
    __s32 prio;
    __s32 target_cpu;
};

struct tp_sched_switch {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;

    char  prev_comm[16];
    __s32 prev_pid;
    __s32 prev_prio;
    __s64 prev_state;

    char  next_comm[16];
    __s32 next_pid;
    __s32 next_prio;
};

static __always_inline __u32 log2_u64(__u64 v)
{
    __u32 r = 0;
    while (v >>= 1) r++;
    return r;
}

// pid -> wakeup ts(ns)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, __u32);
    __type(value, __u64);
} start SEC(".maps");

// global histogram(per-cpu): bins=log2(us)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64[XTOP_HIST_BINS]);
} runq_hist SEC(".maps");

SEC("tracepoint/sched/sched_wakeup")
int on_wakeup(struct tp_sched_wakeup *ctx)
{
    __u32 pid = (__u32)ctx->pid;
    if (pid == 0) return 0;

    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &pid, &now, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_wakeup_new")
int on_wakeup_new(struct tp_sched_wakeup *ctx)
{
    __u32 pid = (__u32)ctx->pid;
    if (pid == 0) return 0;

    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &pid, &now, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_switch")
int on_switch(struct tp_sched_switch *ctx)
{
    __u32 pid = (__u32)ctx->next_pid;
    if (pid == 0) return 0;

    __u64 *tsp = bpf_map_lookup_elem(&start, &pid);
    if (!tsp) return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 delta_ns = (now > *tsp) ? (now - *tsp) : 0;

    __u64 us = delta_ns / 1000;
    if (us == 0) us = 1;

    __u32 b = log2_u64(us);
    if (b >= XTOP_HIST_BINS) b = XTOP_HIST_BINS - 1;

    __u32 key = 0;
    __u64 (*hist)[XTOP_HIST_BINS] = bpf_map_lookup_elem(&runq_hist, &key);
    if (hist) (*hist)[b]++;

    bpf_map_delete_elem(&start, &pid);
    return 0;
}
