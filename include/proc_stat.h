#ifndef PROC_STAT_H
#define PROC_STAT_H

#include <stdint.h>
#include "xtop.h"

typedef struct {
    uint64_t user, nice, system, idle, iowait, irq, softirq, steal;
    uint64_t total;
} cpu_sample_t;

int read_cpu_sample(cpu_sample_t *out);
void calc_cpu_usage(const cpu_sample_t *prev, const cpu_sample_t *cur, cpu_usage_t *out);

#endif
