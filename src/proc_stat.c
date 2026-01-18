#include <stdio.h>
#include <string.h>
#include "proc_stat.h"

int read_cpu_sample(cpu_sample_t *out) {
    memset(out, 0, sizeof(*out));

    FILE *f = fopen("/proc/stat", "r");
    if (!f) return -1;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "cpu ", 4) == 0) {
            unsigned long long user=0,nice=0,system=0,idle=0,iowait=0,irq=0,softirq=0,steal=0;
            (void)sscanf(line, "cpu  %llu %llu %llu %llu %llu %llu %llu %llu",
                         &user,&nice,&system,&idle,&iowait,&irq,&softirq,&steal);

            out->user = user;
            out->nice = nice;
            out->system = system;
            out->idle = idle;
            out->iowait = iowait;
            out->irq = irq;
            out->softirq = softirq;
            out->steal = steal;

            out->total = out->user + out->nice + out->system + out->idle +
                         out->iowait + out->irq + out->softirq + out->steal;
            break;
        }
    }

    fclose(f);
    return 0;
}

static double pct(uint64_t part, uint64_t total) {
    if (total == 0) return 0.0;
    return (double)part * 100.0 / (double)total;
}

void calc_cpu_usage(const cpu_sample_t *prev, const cpu_sample_t *cur, cpu_usage_t *out) {
    memset(out, 0, sizeof(*out));

    uint64_t du = (cur->user    >= prev->user)    ? (cur->user    - prev->user)    : 0;
    uint64_t dn = (cur->nice    >= prev->nice)    ? (cur->nice    - prev->nice)    : 0;
    uint64_t ds = (cur->system  >= prev->system)  ? (cur->system  - prev->system)  : 0;
    uint64_t di = (cur->idle    >= prev->idle)    ? (cur->idle    - prev->idle)    : 0;
    uint64_t dw = (cur->iowait  >= prev->iowait)  ? (cur->iowait  - prev->iowait)  : 0;
    uint64_t dq = (cur->irq     >= prev->irq)     ? (cur->irq     - prev->irq)     : 0;
    uint64_t dS = (cur->softirq >= prev->softirq) ? (cur->softirq - prev->softirq) : 0;
    uint64_t dt = (cur->steal   >= prev->steal)   ? (cur->steal   - prev->steal)   : 0;

    uint64_t total = du + dn + ds + di + dw + dq + dS + dt;

    out->usr     = pct(du + dn, total);
    out->sys     = pct(ds + dq + dS, total);
    out->idle    = pct(di, total);
    out->iowait  = pct(dw, total);
    out->irq     = pct(dq, total);
    out->softirq = pct(dS, total);
    out->steal   = pct(dt, total);
}
