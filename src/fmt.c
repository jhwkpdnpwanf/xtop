#include <stdio.h>
#include <string.h>
#include "fmt.h"

void clear_screen_if_needed(bool batch) {
    if (batch) return;
    fputs("\033[H\033[J", stdout);
}

void print_header(const cpu_usage_t *cu, const meminfo_t *mi, const task_counts_t *tc, bool batch) {
    (void)batch;

    double mem_used_kb = 0.0;
    if (mi->mem_total_kb > 0) {
        uint64_t avail = mi->mem_avail_kb ? mi->mem_avail_kb : 0;
        mem_used_kb = (double)(mi->mem_total_kb - avail);
    }

    printf("Tasks: %llu total, %llu running, %llu sleeping, %llu stopped, %llu zombie\n",
           (unsigned long long)tc->total,
           (unsigned long long)tc->running,
           (unsigned long long)tc->sleeping,
           (unsigned long long)tc->stopped,
           (unsigned long long)tc->zombie);

    printf("CPU: %5.1f%% usr  %5.1f%% sys  %5.1f%% idle  %5.1f%% iowait  %4.1f%% irq  %4.1f%% sirq\n",
           cu->usr, cu->sys, cu->idle, cu->iowait, cu->irq, cu->softirq);

    printf("MEM: %.0f MiB / %.0f MiB (Avail %.0f MiB)\n\n",
           mem_used_kb / 1024.0,
           (double)mi->mem_total_kb / 1024.0,
           (double)mi->mem_avail_kb / 1024.0);
}

static void fmt_time_ticks_frac(uint64_t ticks, long clk_tck, char out[32]) {
    if (clk_tck <= 0) clk_tck = 100;

    // ticks -> milliseconds
    uint64_t ms = (ticks * 1000ULL) / (uint64_t)clk_tck;

    uint64_t hours = ms / (3600ULL * 1000ULL);
    ms %= (3600ULL * 1000ULL);

    uint64_t mins = ms / (60ULL * 1000ULL);
    ms %= (60ULL * 1000ULL);

    uint64_t secs = ms / 1000ULL;
    uint64_t frac = (ms % 1000ULL) / 10ULL; // 00~99 (centiseconds)

    if (hours > 0) {
        snprintf(out, 32, "%02llu:%02llu:%02llu.%02llu",
                 (unsigned long long)hours,
                 (unsigned long long)mins,
                 (unsigned long long)secs,
                 (unsigned long long)frac);
    } else {

        snprintf(out, 32, "%02llu:%02llu.%02llu",
                 (unsigned long long)mins,
                 (unsigned long long)secs,
                 (unsigned long long)frac);
    }
}

void print_table(const proc_list_t *pl, int top_n, bool batch, long clk_tck) {
    (void)batch;

    printf("%-7s  %-10s  %-2s  %8s  %8s  %-11s  %-30s\n",
           "PID", "USER", "S", "%CPU", "%MEM", "TIME", "COMMAND");

    int n = (int)pl->len;
    if (top_n > 0 && top_n < n) n = top_n;

    for (int i = 0; i < n; i++) {
        const proc_entry_t *e = &pl->items[i];
        char tbuf[32];
        fmt_time_ticks_frac(e->time_ticks_total, clk_tck, tbuf);

        printf("%-7d  %-10.10s  %-2c  %8.1f  %8.1f  %-11s  %-30.30s\n",
               (int)e->pid,
               e->user[0] ? e->user : "?",
               e->state ? e->state : '?',
               e->cpu_pct,
               e->mem_pct,
               tbuf,
               e->comm);
    }
}
