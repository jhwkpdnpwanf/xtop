#pragma once

#define XTOP_MAX_SOFTIRQS 64
#define XTOP_HIST_BINS    64

#define XTOP_SOFTIRQ_NET_RX 3

typedef struct {
    double net_rx_softirq_pct; // interval 내 net_rx softirq 비율(%)
    double runq_p95_ms;        // interval 내 runq 95백분위수(ms)

    // runq 히스토그램 delta(시각화/분석용)
    unsigned long long runq_hist_delta[XTOP_HIST_BINS];
} xtop_bpf_stats_t;
