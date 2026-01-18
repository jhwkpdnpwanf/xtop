#ifndef XTOP_H
#define XTOP_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#define XTOP_COMM_MAX 256
#define XTOP_USER_MAX 64

typedef enum {
    ORDER_CPU = 0,
    ORDER_MEM,
    ORDER_TIME,
    ORDER_PID,
} xtop_order_t;

typedef struct {
    double usr;
    double sys;
    double idle;
    double iowait;
    double irq;
    double softirq;
    double steal;
} cpu_usage_t;

typedef struct {
    uint64_t mem_total_kb;
    uint64_t mem_avail_kb;
    uint64_t mem_free_kb;
    uint64_t buffers_kb;
    uint64_t cached_kb;
} meminfo_t;

typedef struct {
    uint64_t total;
    uint64_t running;   // R
    uint64_t sleeping;  // S, D
    uint64_t stopped;   // T, t
    uint64_t zombie;    // Z
    uint64_t other;
} task_counts_t;

typedef struct {
    pid_t pid;
    pid_t ppid;

    char comm[XTOP_COMM_MAX];

    char state;               // /proc/[pid]/stat state
    uid_t uid;                // real uid
    char user[XTOP_USER_MAX]; // username (best-effort)

    uint64_t utime_ticks;     // /proc/[pid]/stat
    uint64_t stime_ticks;
    uint64_t time_ticks_total;

    uint64_t rss_pages;       // /proc/[pid]/statm
    uint64_t vmsize_pages;

    // calculated fields
    double cpu_pct;
    double mem_pct;
} proc_entry_t;

typedef struct {
    double delay_sec;       // -d
    int iterations;         // -n
    bool batch;             // -b
    int top_n;              // -k
    xtop_order_t order;     // -o
    pid_t only_pid;         // -p

    // eBPF 관련 옵션
    bool ebpf;
    uint64_t min_lat_us;
} xtop_opts_t;

#endif
