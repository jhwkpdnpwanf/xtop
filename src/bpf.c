#define _GNU_SOURCE
#include <errno.h>
#include <math.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/types.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xtop_bpf.h"
#include "bpf.h"

#include "xtop_softirq.skel.h"
#include "xtop_runqlat.skel.h"

struct xtop_bpf_ctx {
    struct xtop_softirq_bpf *softirq;
    struct xtop_runqlat_bpf *runqlat;

    __u64 prev_softirq_total[XTOP_MAX_SOFTIRQS];
    __u64 prev_runq_hist_total[XTOP_HIST_BINS];
    bool have_prev;
    bool verbose;
};

static int libbpf_print_fn(enum libbpf_print_level lvl, const char *fmt, va_list args)
{
    // verbose일 때만 출력(초기 attach 실패 원인 잡기 위해)
    return vfprintf(stderr, fmt, args);
}

static double clamp_double(double x, double lo, double hi)
{
    if (x < lo) return lo;
    if (x > hi) return hi;
    return x;
}

// hist_delta에서 p95 지연시간(밀리초 단위) 계산
static double hist_p95_ms_from_delta(const __u64 *hist_delta)
{
    __u64 total = 0;
    for (int i = 0; i < XTOP_HIST_BINS; i++) total += hist_delta[i];
    if (total == 0) return 0.0;

    __u64 target = (__u64)ceil((double)total * 0.95);
    __u64 cum = 0;

    for (int i = 0; i < XTOP_HIST_BINS; i++) {
        cum += hist_delta[i];
        if (cum >= target) {
            double us = (double)(1ULL << i);
            return us / 1000.0;
        }
    }
    return (double)(1ULL << (XTOP_HIST_BINS - 1)) / 1000.0;
}

// 각 CPU별로 저장된 u64 배열을 모두 더해서 out에 저장
static int read_percpu_u64_array_sum(int map_fd, const void *key, size_t value_sz, __u64 *out, size_t out_n)
{
    int ncpu = libbpf_num_possible_cpus();
    if (ncpu <= 0) return -1;

    void *buf = calloc((size_t)ncpu, value_sz);
    if (!buf) return -1;

    if (bpf_map_lookup_elem(map_fd, key, buf) != 0) {
        free(buf);
        return -1;
    }

    // sum per-cpu values
    for (int c = 0; c < ncpu; c++) {
        __u64 *arr = (__u64 *)((char *)buf + (size_t)c * value_sz);
        for (size_t i = 0; i < out_n; i++) out[i] += arr[i];
    }

    free(buf);
    return 0;
}

int xtop_bpf_init(xtop_bpf_ctx_t **out, bool verbose)
{
    *out = NULL;
    struct xtop_bpf_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return -ENOMEM;

    ctx->verbose = verbose;
    if (verbose) libbpf_set_print(libbpf_print_fn);

    // open/load/attach softirq
    ctx->softirq = xtop_softirq_bpf__open();
    if (!ctx->softirq) goto fail;

    if (xtop_softirq_bpf__load(ctx->softirq) != 0) goto fail;
    if (xtop_softirq_bpf__attach(ctx->softirq) != 0) goto fail;

    // open/load/attach runqlat
    ctx->runqlat = xtop_runqlat_bpf__open();
    if (!ctx->runqlat) goto fail;

    if (xtop_runqlat_bpf__load(ctx->runqlat) != 0) goto fail;
    if (xtop_runqlat_bpf__attach(ctx->runqlat) != 0) goto fail;

    ctx->have_prev = false;
    *out = ctx;
    return 0;

fail:
    xtop_bpf_destroy(ctx);
    return -1;
}

void xtop_bpf_destroy(xtop_bpf_ctx_t *ctx_)
{
    if (!ctx_) return;
    struct xtop_bpf_ctx *ctx = ctx_;

    if (ctx->runqlat) xtop_runqlat_bpf__destroy(ctx->runqlat);
    if (ctx->softirq) xtop_softirq_bpf__destroy(ctx->softirq);
    free(ctx);
}

int xtop_bpf_snapshot(xtop_bpf_ctx_t *ctx_, double interval_sec, int ncpu, xtop_bpf_stats_t *stats)
{
    struct xtop_bpf_ctx *ctx = ctx_;
    memset(stats, 0, sizeof(*stats));

    if (!ctx || !ctx->softirq || !ctx->runqlat) return -1;
    if (interval_sec <= 0) interval_sec = 1.0;
    if (ncpu <= 0) ncpu = 1;

    // read current values from BPF maps
    __u32 key0 = 0;

    __u64 cur_softirq[XTOP_MAX_SOFTIRQS] = {0};
    int softirq_map_fd = bpf_map__fd(ctx->softirq->maps.softirq_time_ns);
    if (softirq_map_fd < 0) return -1;
    if (read_percpu_u64_array_sum(softirq_map_fd, &key0, sizeof(__u64) * XTOP_MAX_SOFTIRQS, cur_softirq, XTOP_MAX_SOFTIRQS) != 0)
        return -1;

    __u64 cur_hist[XTOP_HIST_BINS] = {0};
    int hist_map_fd = bpf_map__fd(ctx->runqlat->maps.runq_hist);
    if (hist_map_fd < 0) return -1;
    if (read_percpu_u64_array_sum(hist_map_fd, &key0, sizeof(__u64) * XTOP_HIST_BINS, cur_hist, XTOP_HIST_BINS) != 0)
        return -1;

    if (!ctx->have_prev) {
        memcpy(ctx->prev_softirq_total, cur_softirq, sizeof(cur_softirq));
        memcpy(ctx->prev_runq_hist_total, cur_hist, sizeof(cur_hist));
        ctx->have_prev = true;
        return 0; // first snapshot, no delta
    }

    // compute deltas
    __u64 delta_softirq[XTOP_MAX_SOFTIRQS] = {0};
    for (int i = 0; i < XTOP_MAX_SOFTIRQS; i++) {
        delta_softirq[i] = (cur_softirq[i] >= ctx->prev_softirq_total[i]) ? (cur_softirq[i] - ctx->prev_softirq_total[i]) : 0;
    }

    __u64 delta_hist[XTOP_HIST_BINS] = {0};
    for (int i = 0; i < XTOP_HIST_BINS; i++) {
        delta_hist[i] = (cur_hist[i] >= ctx->prev_runq_hist_total[i]) ? (cur_hist[i] - ctx->prev_runq_hist_total[i]) : 0;
        stats->runq_hist_delta[i] = delta_hist[i];
    }

    memcpy(ctx->prev_softirq_total, cur_softirq, sizeof(cur_softirq));
    memcpy(ctx->prev_runq_hist_total, cur_hist, sizeof(cur_hist));

    // compute stats from deltas
    double interval_ns_total = interval_sec * 1e9 * (double)ncpu;
    double netrx_ns = (double)delta_softirq[XTOP_SOFTIRQ_NET_RX];
    double pct = (interval_ns_total > 0) ? (netrx_ns / interval_ns_total * 100.0) : 0.0;
    stats->net_rx_softirq_pct = clamp_double(pct, 0.0, 100.0);

    // runq p95
    stats->runq_p95_ms = hist_p95_ms_from_delta(delta_hist);
    return 0;
}
