// src/xtop.c
#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "../include/xtop.h"
#include "xtop.skel.h"


#define RQ_BUCKETS 9
#define SOFTIRQ_VECS 10

static const char *rq_labels[RQ_BUCKETS] = {
    "0-1us","1-2us","2-4us","4-8us","8-16us","16-32us","32-64us","64-128us","128+us"
};

static const char* softirq_name(int v) {
    switch (v) {
        case 0: return "HI";
        case 1: return "TIMER";
        case 2: return "NET_TX";
        case 3: return "NET_RX";
        case 4: return "BLOCK";
        case 5: return "IRQ_POLL";
        case 6: return "TASKLET";
        case 7: return "SCHED";
        case 8: return "HRTIMER";
        case 9: return "RCU";
        default: return "UNKNOWN";
    }
}

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int sig) { (void)sig; g_stop = 1; }


static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  -d <sec>     Refresh interval (default: 1)\n"
        "  -n <N>       Number of updates before exit (0=forever)\n"
        "  -b           Batch mode (no screen clear)\n"
        "  -k <N>       Show top N processes (default: 20)\n"
        "  -o <key>     Sort by: cpu|mem|time|pid (default: cpu)\n"
        "  -p <pid>     Show only specific PID\n",
        prog
    );
}

static xtop_order_t parse_order(const char *s) {
    if (!s) return ORDER_CPU;
    if (strcmp(s, "cpu") == 0)  return ORDER_CPU;
    if (strcmp(s, "mem") == 0)  return ORDER_MEM;
    if (strcmp(s, "time") == 0) return ORDER_TIME;
    if (strcmp(s, "pid") == 0)  return ORDER_PID;
    return ORDER_CPU;
}

static int parse_args(int argc, char **argv, xtop_opts_t *opt) {
    *opt = (xtop_opts_t){
        .delay_sec = 1.0,
        .iterations = 0,
        .batch = false,
        .top_n = 20,
        .order = ORDER_CPU,
        .only_pid = 0,
    };

    int c;
    while ((c = getopt(argc, argv, "d:n:bk:o:p:")) != -1) {
        switch (c) {
        case 'd':
            opt->delay_sec = atof(optarg);
            if (opt->delay_sec <= 0) opt->delay_sec = 1.0;
            break;
        case 'n':
            opt->iterations = atoi(optarg);
            if (opt->iterations < 0) opt->iterations = 0;
            break;
        case 'b':
            opt->batch = true;
            break;
        case 'k':
            opt->top_n = atoi(optarg);
            if (opt->top_n <= 0) opt->top_n = 20;
            break;
        case 'o':
            opt->order = parse_order(optarg);
            break;
        case 'p':
            opt->only_pid = (pid_t)atoi(optarg);
            if (opt->only_pid < 0) opt->only_pid = 0;
            break;
        default:
            usage(argv[0]);
            return -1;
        }
    }
    return 0;
}

static void sleep_sec(double sec) {
    if (sec <= 0) return;
    struct timespec ts;
    ts.tv_sec = (time_t)sec;
    ts.tv_nsec = (long)((sec - (double)ts.tv_sec) * 1000000000.0);
    if (ts.tv_nsec < 0) ts.tv_nsec = 0;
    nanosleep(&ts, NULL);
}


typedef struct {
    proc_entry_t *items;
    size_t len;
    size_t cap;
} proc_list_t;

static int ensure_cap(proc_list_t *pl, size_t need) {
    if (pl->cap >= need) return 0;
    size_t newcap = pl->cap ? pl->cap * 2 : 256;
    while (newcap < need) newcap *= 2;
    proc_entry_t *p = realloc(pl->items, newcap * sizeof(proc_entry_t));
    if (!p) return -1;
    pl->items = p;
    pl->cap = newcap;
    return 0;
}

static void proc_list_free(proc_list_t *pl) {
    free(pl->items);
    pl->items = NULL;
    pl->len = 0;
    pl->cap = 0;
}

typedef struct {
    uint64_t user, nice, system, idle, iowait, irq, softirq, steal;
    uint64_t total;
} cpu_sample_t;

static int read_cpu_sample(cpu_sample_t *out) {
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

static double pct_u64(uint64_t part, uint64_t total) {
    if (total == 0) return 0.0;
    return (double)part * 100.0 / (double)total;
}

static void calc_cpu_usage(const cpu_sample_t *prev, const cpu_sample_t *cur, cpu_usage_t *out) {
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

    out->usr     = pct_u64(du + dn, total);
    out->sys     = pct_u64(ds + dq + dS, total);
    out->idle    = pct_u64(di, total);
    out->iowait  = pct_u64(dw, total);
    out->irq     = pct_u64(dq, total);
    out->softirq = pct_u64(dS, total);
    out->steal   = pct_u64(dt, total);
}

static int read_meminfo(meminfo_t *out) {
    memset(out, 0, sizeof(*out));

    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return -1;

    char key[64];
    unsigned long long val = 0;
    char unit[16];

    while (fscanf(f, "%63s %llu %15s\n", key, &val, unit) == 3) {
        if (strcmp(key, "MemTotal:") == 0) out->mem_total_kb = val;
        else if (strcmp(key, "MemAvailable:") == 0) out->mem_avail_kb = val;
        else if (strcmp(key, "MemFree:") == 0) out->mem_free_kb = val;
        else if (strcmp(key, "Buffers:") == 0) out->buffers_kb = val;
        else if (strcmp(key, "Cached:") == 0) out->cached_kb = val;
    }
    fclose(f);

    if (out->mem_avail_kb == 0) {
        out->mem_avail_kb = out->mem_free_kb + out->buffers_kb + out->cached_kb;
    }
    return 0;
}

static int read_pid_stat(pid_t pid, proc_entry_t *e) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char buf[4096];
    if (!fgets(buf, sizeof(buf), f)) { fclose(f); return -1; }
    fclose(f);

    char *lp = strchr(buf, '(');
    char *rp = strrchr(buf, ')');
    if (!lp || !rp || rp <= lp) return -1;

    size_t clen = (size_t)(rp - lp - 1);
    if (clen >= sizeof(e->comm)) clen = sizeof(e->comm) - 1;
    memcpy(e->comm, lp + 1, clen);
    e->comm[clen] = '\0';

    e->pid = pid;

    char *rest = rp + 2;
    int field = 3;
    char *save = NULL;
    char *tok = strtok_r(rest, " ", &save);

    char state = 0;
    long long ppid = 0;
    uint64_t utime = 0, stime = 0;

    while (tok) {
        if (field == 3) state = tok[0];
        else if (field == 4) ppid = atoll(tok);
        else if (field == 14) utime = (uint64_t)strtoull(tok, NULL, 10);
        else if (field == 15) { stime = (uint64_t)strtoull(tok, NULL, 10); break; }
        field++;
        tok = strtok_r(NULL, " ", &save);
    }

    e->state = state;
    e->ppid = (pid_t)ppid;
    e->utime_ticks = utime;
    e->stime_ticks = stime;
    e->time_ticks_total = utime + stime;
    return 0;
}

static int read_pid_statm(pid_t pid, proc_entry_t *e) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/statm", pid);

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    unsigned long long size=0, rss=0;
    if (fscanf(f, "%llu %llu", &size, &rss) != 2) { fclose(f); return -1; }
    fclose(f);

    e->vmsize_pages = (uint64_t)size;
    e->rss_pages = (uint64_t)rss;
    return 0;
}

static int read_pid_uid(pid_t pid, proc_entry_t *e) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    e->uid = 0;
    e->user[0] = '\0';

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Uid:", 4) == 0) {
            unsigned int ruid = 0;
            if (sscanf(line, "Uid:\t%u", &ruid) == 1) e->uid = (uid_t)ruid;
            break;
        }
    }
    fclose(f);

    struct passwd pw, *pwp = NULL;
    char buf[4096];
    if (getpwuid_r(e->uid, &pw, buf, sizeof(buf), &pwp) == 0 && pwp) {
        snprintf(e->user, sizeof(e->user), "%s", pw.pw_name);
    } else {
        snprintf(e->user, sizeof(e->user), "%u", (unsigned)e->uid);
    }
    return 0;
}

static int scan_processes(proc_list_t *out, pid_t only_pid) {
    memset(out, 0, sizeof(*out));

    if (only_pid > 0) {
        proc_entry_t e; memset(&e, 0, sizeof(e));
        if (read_pid_stat(only_pid, &e) != 0) return -1;
        (void)read_pid_statm(only_pid, &e);
        (void)read_pid_uid(only_pid, &e);
        if (ensure_cap(out, 1) != 0) return -1;
        out->items[out->len++] = e;
        return 0;
    }

    DIR *d = opendir("/proc");
    if (!d) return -1;

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        bool ok = true;
        for (const char *p = de->d_name; *p; p++) {
            if (!isdigit((unsigned char)*p)) { ok = false; break; }
        }
        if (!ok) continue;

        pid_t pid = (pid_t)atoi(de->d_name);
        proc_entry_t e; memset(&e, 0, sizeof(e));
        if (read_pid_stat(pid, &e) != 0) continue;
        (void)read_pid_statm(pid, &e);
        (void)read_pid_uid(pid, &e);

        if (ensure_cap(out, out->len + 1) != 0) { closedir(d); return -1; }
        out->items[out->len++] = e;
    }

    closedir(d);
    return 0;
}

static const proc_entry_t* find_prev(const proc_list_t *prev, pid_t pid) {
    for (size_t i = 0; i < prev->len; i++) {
        if (prev->items[i].pid == pid) return &prev->items[i];
    }
    return NULL;
}

static void compute_process_metrics(proc_list_t *cur,
                                    const proc_list_t *prev,
                                    uint64_t cpu_total_delta_ticks,
                                    int ncpu,
                                    uint64_t mem_total_kb,
                                    long page_size) {
    for (size_t i = 0; i < cur->len; i++) {
        proc_entry_t *e = &cur->items[i];
        const proc_entry_t *p = find_prev(prev, e->pid);

        uint64_t cur_ticks = e->utime_ticks + e->stime_ticks;
        uint64_t prev_ticks = p ? (p->utime_ticks + p->stime_ticks) : cur_ticks;
        uint64_t dticks = (cur_ticks >= prev_ticks) ? (cur_ticks - prev_ticks) : 0;

        double base = (cpu_total_delta_ticks > 0) ? ((double)dticks / (double)cpu_total_delta_ticks) : 0.0;
        e->cpu_pct = base * 100.0 * (double)ncpu;

        uint64_t rss_bytes = e->rss_pages * (uint64_t)page_size;
        uint64_t mem_total_bytes = mem_total_kb * 1024ULL;
        e->mem_pct = (mem_total_bytes > 0) ? ((double)rss_bytes * 100.0 / (double)mem_total_bytes) : 0.0;
    }
}

static int cmp_cpu_desc(const void *a, const void *b) {
    const proc_entry_t *pa = a, *pb = b;
    if (pa->cpu_pct < pb->cpu_pct) return 1;
    if (pa->cpu_pct > pb->cpu_pct) return -1;
    return (pa->pid > pb->pid) - (pa->pid < pb->pid);
}
static int cmp_mem_desc(const void *a, const void *b) {
    const proc_entry_t *pa = a, *pb = b;
    if (pa->mem_pct < pb->mem_pct) return 1;
    if (pa->mem_pct > pb->mem_pct) return -1;
    return (pa->pid > pb->pid) - (pa->pid < pb->pid);
}
static int cmp_time_desc(const void *a, const void *b) {
    const proc_entry_t *pa = a, *pb = b;
    if (pa->time_ticks_total < pb->time_ticks_total) return 1;
    if (pa->time_ticks_total > pb->time_ticks_total) return -1;
    return (pa->pid > pb->pid) - (pa->pid < pb->pid);
}
static int cmp_pid_asc(const void *a, const void *b) {
    const proc_entry_t *pa = a, *pb = b;
    return (pa->pid > pb->pid) - (pa->pid < pb->pid);
}

static int sort_processes(proc_list_t *pl, xtop_order_t order) {
    if (!pl || !pl->items) return -1;
    switch (order) {
    case ORDER_MEM:  qsort(pl->items, pl->len, sizeof(proc_entry_t), cmp_mem_desc); break;
    case ORDER_TIME: qsort(pl->items, pl->len, sizeof(proc_entry_t), cmp_time_desc); break;
    case ORDER_PID:  qsort(pl->items, pl->len, sizeof(proc_entry_t), cmp_pid_asc); break;
    case ORDER_CPU:
    default:         qsort(pl->items, pl->len, sizeof(proc_entry_t), cmp_cpu_desc); break;
    }
    return 0;
}

static task_counts_t count_tasks(const proc_list_t *pl) {
    task_counts_t tc = {0};
    tc.total = pl ? pl->len : 0;
    if (!pl) return tc;

    for (size_t i = 0; i < pl->len; i++) {
        char s = pl->items[i].state;
        switch (s) {
        case 'R': tc.running++; break;
        case 'S':
        case 'D': tc.sleeping++; break;
        case 'T':
        case 't': tc.stopped++; break;
        case 'Z': tc.zombie++; break;
        default: tc.other++; break;
        }
    }
    return tc;
}

static void clear_screen_if_needed(bool batch) {
    if (batch) return;
    fputs("\033[H\033[J", stdout);
}

// Format time ticks
static void fmt_time_ticks_frac(uint64_t ticks, long clk_tck, char out[32]) {
    if (clk_tck <= 0) clk_tck = 100;
    uint64_t ms = (ticks * 1000ULL) / (uint64_t)clk_tck;

    uint64_t hours = ms / (3600ULL * 1000ULL);
    ms %= (3600ULL * 1000ULL);
    uint64_t mins = ms / (60ULL * 1000ULL);
    ms %= (60ULL * 1000ULL);
    uint64_t secs = ms / 1000ULL;
    uint64_t frac = (ms % 1000ULL) / 10ULL;

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


// eBPF map read helpers
static int ncpu_online(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return (n > 0) ? (int)n : 1;
}


static int read_percpu_array_u64(int map_fd, int nkeys, unsigned long long *out_sum) {
    memset(out_sum, 0, sizeof(unsigned long long) * (size_t)nkeys);

    int ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0) return -1;

    size_t per_sz = sizeof(__u64) * (size_t)ncpus;
    __u64 *percpu = malloc(per_sz);
    if (!percpu) return -1;

    for (int k = 0; k < nkeys; k++) {
        __u32 key = (__u32)k;
        memset(percpu, 0, per_sz);

        if (bpf_map_lookup_elem(map_fd, &key, percpu) != 0)
            continue;

        unsigned long long sum = 0;
        for (int c = 0; c < ncpus; c++)
            sum += (unsigned long long)percpu[c];

        out_sum[k] = sum;
    }

    free(percpu);
    return 0;
}

static void bar(char *dst, size_t dstsz, unsigned long long val, unsigned long long maxv, int width) {
    if (dstsz == 0) return;
    if (width < 1) { dst[0] = 0; return; }

    int n = 0;
    if (maxv > 0) n = (int)((val * (unsigned long long)width) / maxv);
    if (n < 0) n = 0;
    if (n > width) n = width;

    int pos = 0;
    for (int i = 0; i < n && pos+1 < (int)dstsz; i++) dst[pos++] = '#';
    for (int i = n; i < width && pos+1 < (int)dstsz; i++) dst[pos++] = ' ';
    dst[pos] = 0;
}


// Main loop
int main(int argc, char **argv) {
    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    xtop_opts_t opt;
    if (parse_args(argc, argv, &opt) != 0) return 2;

    long clk_tck = sysconf(_SC_CLK_TCK);
    long page_size = sysconf(_SC_PAGESIZE);
    int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (clk_tck <= 0) clk_tck = 100;
    if (page_size <= 0) page_size = 4096;
    if (ncpu <= 0) ncpu = 1;

    // BPF skeleton load/attach
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    struct xtop_bpf *skel = xtop_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "BPF open/load failed (need root? vmlinux.h?)\n");
        return 1;
    }
    if (xtop_bpf__attach(skel) != 0) {
        fprintf(stderr, "BPF attach failed\n");
        xtop_bpf__destroy(skel);
        return 1;
    }

    int fd_rq_hist = bpf_map__fd(skel->maps.rq_hist);
    int fd_softirq_time = bpf_map__fd(skel->maps.softirq_time);

    cpu_sample_t cpu_prev = {0}, cpu_cur = {0};
    cpu_usage_t usage_cpu = {0};
    meminfo_t mi = {0};

    proc_list_t prev = {0}, cur = {0};

    unsigned long long rq_prev[RQ_BUCKETS] = {0};
    unsigned long long si_prev[SOFTIRQ_VECS] = {0};

    if (read_cpu_sample(&cpu_prev) != 0) { fprintf(stderr, "Failed /proc/stat\n"); return 1; }
    if (read_meminfo(&mi) != 0) { fprintf(stderr, "Failed /proc/meminfo\n"); return 1; }
    if (scan_processes(&prev, opt.only_pid) != 0) { fprintf(stderr, "Failed scan /proc\n"); return 1; }

    int iter = 0;
    for (;;) {
        if (g_stop) break;
        sleep_sec(opt.delay_sec);

        if (read_cpu_sample(&cpu_cur) != 0) break;
        if (read_meminfo(&mi) != 0) break;

        proc_list_free(&cur);
        if (scan_processes(&cur, opt.only_pid) != 0) break;

        calc_cpu_usage(&cpu_prev, &cpu_cur, &usage_cpu);
        uint64_t cpu_total_delta = (cpu_cur.total >= cpu_prev.total) ? (cpu_cur.total - cpu_prev.total) : 0;

        compute_process_metrics(&cur, &prev, cpu_total_delta, ncpu, mi.mem_total_kb, page_size);
        sort_processes(&cur, opt.order);
        task_counts_t tc = count_tasks(&cur);

        // eBPF read (sum per-cpu) + delta
        unsigned long long rq_sum[RQ_BUCKETS] = {0}, si_sum[SOFTIRQ_VECS] = {0};
        unsigned long long rq_delta[RQ_BUCKETS] = {0}, si_delta[SOFTIRQ_VECS] = {0};

        (void)read_percpu_array_u64(fd_rq_hist, RQ_BUCKETS, rq_sum);
        (void)read_percpu_array_u64(fd_softirq_time, SOFTIRQ_VECS, si_sum);

        unsigned long long rq_max = 1;
        for (int i = 0; i < RQ_BUCKETS; i++) {
            rq_delta[i] = (rq_sum[i] >= rq_prev[i]) ? (rq_sum[i] - rq_prev[i]) : 0;
            rq_prev[i] = rq_sum[i];
            if (rq_delta[i] > rq_max) rq_max = rq_delta[i];
        }

        unsigned long long si_max = 1, si_total = 0;
        for (int i = 0; i < SOFTIRQ_VECS; i++) {
            si_delta[i] = (si_sum[i] >= si_prev[i]) ? (si_sum[i] - si_prev[i]) : 0;
            si_prev[i] = si_sum[i];
            si_total += si_delta[i];
            if (si_delta[i] > si_max) si_max = si_delta[i];
        }

        // render
        clear_screen_if_needed(opt.batch);

        // tasks/cpu/mem (compact)
        double mem_used_kb = (mi.mem_total_kb > 0 && mi.mem_avail_kb <= mi.mem_total_kb)
                           ? (double)(mi.mem_total_kb - mi.mem_avail_kb) : 0.0;

        printf("Tasks:%llu total R:%llu S:%llu T:%llu Z:%llu | MEM: %.0f/%.0f MiB (Avail %.0f MiB)\n",
               (unsigned long long)tc.total,
               (unsigned long long)tc.running,
               (unsigned long long)tc.sleeping,
               (unsigned long long)tc.stopped,
               (unsigned long long)tc.zombie,
               mem_used_kb / 1024.0,
               (double)mi.mem_total_kb / 1024.0,
               (double)mi.mem_avail_kb / 1024.0);

        printf("CPU: usr %5.1f sys %5.1f idle %5.1f iow %5.1f irq %4.1f sirq %4.1f | interval %.2fs\n",
               usage_cpu.usr, usage_cpu.sys, usage_cpu.idle, usage_cpu.iowait, usage_cpu.irq, usage_cpu.softirq, opt.delay_sec);

        printf("--------------------------------------------------------------------------------\n");

        // top table
        printf("%-7s %-10s %-2s %7s %7s %-11s %-24s\n", "PID","USER","S","%CPU","%MEM","TIME","COMMAND");
        int n = (int)cur.len;
        int top_n = opt.top_n;
        if (top_n > 0 && top_n < n) n = top_n;
        if (n > 8) n = 8;

        for (int i = 0; i < n; i++) {
            const proc_entry_t *e = &cur.items[i];
            char tbuf[32];
            fmt_time_ticks_frac(e->time_ticks_total, clk_tck, tbuf);
            printf("%-7d %-10.10s %-2c %7.1f %7.1f %-11s %-24.24s\n",
                   (int)e->pid,
                   e->user[0] ? e->user : "?",
                   e->state ? e->state : '?',
                   e->cpu_pct,
                   e->mem_pct,
                   tbuf,
                   e->comm);
        }

        printf("--------------------------------------------------------------------------------\n");
        printf("[eBPF:SCHED] RunQueue Latency (wakeup->onCPU) last %.2fs (counts)\n", opt.delay_sec);

        for (int i = 0; i < RQ_BUCKETS; i++) {
            char g[29];
            bar(g, sizeof(g), rq_delta[i], rq_max, 24);
            printf("  %-7s %8llu | %s\n", rq_labels[i], rq_delta[i], g);
        }

        printf("--------------------------------------------------------------------------------\n");
        printf("[eBPF:IRQ] SoftIRQ time last %.2fs (ms/share)\n", opt.delay_sec);

        // major 5개 + OTHER만 출력
        int majors[5] = {3,4,1,7,9}; // NET_RX, BLOCK, TIMER, SCHED, RCU
        unsigned long long major_sum = 0;
        for (int i = 0; i < 5; i++) major_sum += si_delta[majors[i]];
        unsigned long long other = (si_total >= major_sum) ? (si_total - major_sum) : 0;

        for (int i = 0; i < 5; i++) {
            int v = majors[i];
            double ms = (double)si_delta[v] / 1e6;
            double pct = (si_total > 0) ? (100.0 * (double)si_delta[v] / (double)si_total) : 0.0;
            char g[29];
            bar(g, sizeof(g), si_delta[v], si_max, 24);
            printf("  %-7s %7.1fms %5.1f%% | %s\n", softirq_name(v), ms, pct, g);
        }
        {
            double ms = (double)other / 1e6;
            double pct = (si_total > 0) ? (100.0 * (double)other / (double)si_total) : 0.0;
            char g[29];
            bar(g, sizeof(g), other, si_max, 24);
            printf("  %-7s %7.1fms %5.1f%% | %s\n", "OTHER", ms, pct, g);
        }

        fflush(stdout);

        // rotate snapshots
        cpu_prev = cpu_cur;
        proc_list_free(&prev);
        prev = cur;
        cur.items = NULL; cur.len = 0; cur.cap = 0;

        if (opt.iterations > 0) {
            iter++;
            if (iter >= opt.iterations) break;
        }
    }

    proc_list_free(&prev);
    proc_list_free(&cur);
    xtop_bpf__destroy(skel);
    return 0;
}
