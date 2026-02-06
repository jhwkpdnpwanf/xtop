#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "xtop_bpf.h"

char LICENSE[] SEC("license") = "GPL";


struct tp_softirq_entry {
    __u16 common_type;          /* offset 0 */
    __u8  common_flags;         /* offset 2 */
    __u8  common_preempt_count; /* offset 3 */
    __s32 common_pid;           /* offset 4 */
    __u32 vec;                  /* offset 8 */
};

struct tp_softirq_exit {
    __u16 common_type;
    __u8  common_flags;
    __u8  common_preempt_count;
    __s32 common_pid;
    __u32 vec;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64[XTOP_MAX_SOFTIRQS]);
} softirq_time_ns SEC(".maps");

// per-cpu start time
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} start_ts SEC(".maps");

// per-cpu vec saved at entry
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} start_vec SEC(".maps");

SEC("tracepoint/irq/softirq_entry")
int on_softirq_entry(struct tp_softirq_entry *ctx)
{
    __u32 key = 0;
    __u64 now = bpf_ktime_get_ns();

    __u64 *ts = bpf_map_lookup_elem(&start_ts, &key);
    __u32 *vecp = bpf_map_lookup_elem(&start_vec, &key);
    if (!ts || !vecp) return 0;

    __u32 v = ctx->vec;
    if (v >= XTOP_MAX_SOFTIRQS) v = XTOP_MAX_SOFTIRQS - 1;

    *ts = now;
    *vecp = v;
    return 0;
}

SEC("tracepoint/irq/softirq_exit")
int on_softirq_exit(struct tp_softirq_exit *ctx)
{
    (void)ctx;

    __u32 key = 0;
    __u64 now = bpf_ktime_get_ns();

    __u64 *ts = bpf_map_lookup_elem(&start_ts, &key);
    __u32 *vecp = bpf_map_lookup_elem(&start_vec, &key);
    __u64 (*acc)[XTOP_MAX_SOFTIRQS] = bpf_map_lookup_elem(&softirq_time_ns, &key);
    if (!ts || !vecp || !acc) return 0;

    __u64 start = *ts;
    __u32 v = *vecp;
    if (v >= XTOP_MAX_SOFTIRQS) v = XTOP_MAX_SOFTIRQS - 1;

    if (now > start) {
        (*acc)[v] += (now - start);
    }
    return 0;
}
