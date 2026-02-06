#pragma once
#include <stdbool.h>
#include "xtop_bpf.h"

typedef struct xtop_bpf_ctx xtop_bpf_ctx_t;

int  xtop_bpf_init(xtop_bpf_ctx_t **out, bool verbose);
void xtop_bpf_destroy(xtop_bpf_ctx_t *ctx);

// interval_sec 동안의 delta를 계산해 stats 채움
int  xtop_bpf_snapshot(xtop_bpf_ctx_t *ctx, double interval_sec, int ncpu, xtop_bpf_stats_t *stats);
