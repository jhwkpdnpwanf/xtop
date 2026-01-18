// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
#define _GNU_SOURCE

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} config_map SEC(".maps");

static __always_inline __u64 cfg_u64(__u32 k)
{
    __u64 *v = bpf_map_lookup_elem(&config_map, &k);
    return v ? *v : 0;
}

/* pid -> wakeup timestamp(ns) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u64);
} start SEC(".maps");

/* log2 histogram buckets [0..63], unit=ns */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} hist SEC(".maps");

static __always_inline __u32 log2_u64(__u64 v)
{
    __u32 r = 0;
    if (v == 0)
        return 0;

#pragma unroll
    for (int i = 0; i < 64; i++) {
        if (v <= 1)
            break;
        v >>= 1;
        r++;
    }
    if (r > 63)
        r = 63;
    return r;
}

static __always_inline int should_track(__u32 pid)
{
    __u64 tp = cfg_u64(1); // targ_pid
    if (tp == 0)
        return 1;
    return pid == (__u32)tp;
}


SEC("tp/sched/sched_wakeup")
int tp_wakeup(struct trace_event_raw_sched_wakeup_template *ctx)
{
    __u32 pid = ctx->pid;
    if (!should_track(pid))
        return 0;

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
    return 0;
}

SEC("tp/sched/sched_wakeup_new")
int tp_wakeup_new(struct trace_event_raw_sched_wakeup_template *ctx)
{
    __u32 pid = ctx->pid;
    if (!should_track(pid))
        return 0;

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
    return 0;
}


SEC("tp/sched/sched_switch")
int tp_switch(struct trace_event_raw_sched_switch *ctx)
{
    __u32 next_pid = ctx->next_pid;
    if (!should_track(next_pid))
        return 0;

    __u64 *tsp = bpf_map_lookup_elem(&start, &next_pid);
    if (!tsp)
        return 0;

    __u64 now = bpf_ktime_get_ns();
    __u64 delta = now - *tsp;

    bpf_map_delete_elem(&start, &next_pid);

    __u64 min_ns = cfg_u64(0);
    if (min_ns && delta < min_ns)
        return 0;

    __u32 slot = log2_u64(delta);
    __u64 *cnt = bpf_map_lookup_elem(&hist, &slot);
    if (!cnt)
        return 0;

    __sync_fetch_and_add(cnt, 1);
    return 0;
}
