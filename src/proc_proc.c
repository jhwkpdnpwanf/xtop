#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "proc_proc.h"

static int is_all_digits(const char *s) {
    for (; *s; s++) if (!isdigit((unsigned char)*s)) return 0;
    return 1;
}

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

void proc_list_free(proc_list_t *pl) {
    free(pl->items);
    pl->items = NULL;
    pl->len = 0;
    pl->cap = 0;
}

static int read_pid_stat(pid_t pid, proc_entry_t *e) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char buf[4096];
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return -1;
    }
    fclose(f);

    // pid (comm) state ppid ...
    char *lp = strchr(buf, '(');
    char *rp = strrchr(buf, ')');
    if (!lp || !rp || rp <= lp) return -1;

    // comm
    size_t clen = (size_t)(rp - lp - 1);
    if (clen >= sizeof(e->comm)) clen = sizeof(e->comm) - 1;
    memcpy(e->comm, lp + 1, clen);
    e->comm[clen] = '\0';

    e->pid = pid;

    // parse rest after ") "
    char *rest = rp + 2;

    int field = 3; // rest 첫 토큰이 state(3rd field)
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
    if (fscanf(f, "%llu %llu", &size, &rss) != 2) {
        fclose(f);
        return -1;
    }
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

int scan_processes(proc_list_t *out, pid_t only_pid) {
    memset(out, 0, sizeof(*out));

    // PID 하나만 요청이면 빠른 경로
    if (only_pid > 0) {
        proc_entry_t e;
        memset(&e, 0, sizeof(e));
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
        if (!is_all_digits(de->d_name)) continue;

        pid_t pid = (pid_t)atoi(de->d_name);

        proc_entry_t e;
        memset(&e, 0, sizeof(e));
        if (read_pid_stat(pid, &e) != 0) continue;
        (void)read_pid_statm(pid, &e);
        (void)read_pid_uid(pid, &e);

        if (ensure_cap(out, out->len + 1) != 0) {
            closedir(d);
            return -1;
        }
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

void compute_process_metrics(proc_list_t *cur,
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

int sort_processes(proc_list_t *pl, xtop_order_t order) {
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

task_counts_t count_tasks(const proc_list_t *pl) {
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
