#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "xtop.h"
#include "proc_stat.h"
#include "proc_mem.h"
#include "proc_proc.h"
#include "fmt.h"

<<<<<<< HEAD
=======
#include "bpf.h"

>>>>>>> 6e7074a (ebpf 초기 코드)
static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  -d <sec>     Refresh interval (default: 1)\n"
        "  -n <N>       Number of updates before exit (0=forever)\n"
        "  -b           Batch mode (no screen clear)\n"
        "  -k <N>       Show top N processes (default: 20)\n"
        "  -o <key>     Sort by: cpu|mem|time|pid (default: cpu)\n"
<<<<<<< HEAD
        "  -p <pid>     Show only specific PID\n",
=======
        "  -p <pid>     Show only specific PID\n"
        "  -v           Verbose libbpf logs (useful when attach fails)\n",
>>>>>>> 6e7074a (ebpf 초기 코드)
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

<<<<<<< HEAD
static int parse_args(int argc, char **argv, xtop_opts_t *opt) {
=======
static int parse_args(int argc, char **argv, xtop_opts_t *opt, int *verbose_bpf) {
>>>>>>> 6e7074a (ebpf 초기 코드)
    *opt = (xtop_opts_t){
        .delay_sec = 1.0,
        .iterations = 0,
        .batch = false,
        .top_n = 20,
        .order = ORDER_CPU,
        .only_pid = 0,
    };
<<<<<<< HEAD

    int c;
    while ((c = getopt(argc, argv, "d:n:bk:o:p:")) != -1) {
=======
    *verbose_bpf = 0;

    int c;
    while ((c = getopt(argc, argv, "d:n:bk:o:p:v")) != -1) {
>>>>>>> 6e7074a (ebpf 초기 코드)
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
<<<<<<< HEAD
=======
        case 'v':
            *verbose_bpf = 1;
            break;
>>>>>>> 6e7074a (ebpf 초기 코드)
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

int main(int argc, char **argv) {
    xtop_opts_t opt;
<<<<<<< HEAD
    if (parse_args(argc, argv, &opt) != 0) return 2;
=======
    int verbose_bpf = 0;
    if (parse_args(argc, argv, &opt, &verbose_bpf) != 0) return 2;
>>>>>>> 6e7074a (ebpf 초기 코드)

    long clk_tck = sysconf(_SC_CLK_TCK);
    long page_size = sysconf(_SC_PAGESIZE);
    int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (clk_tck <= 0) clk_tck = 100;
    if (page_size <= 0) page_size = 4096;
    if (ncpu <= 0) ncpu = 1;

    cpu_sample_t cpu_prev = {0}, cpu_cur = {0};
    cpu_usage_t usage_cpu = {0};
    meminfo_t mi = {0};

    proc_list_t prev = {0}, cur = {0};

<<<<<<< HEAD
    // 초기 스냅샷
    if (read_cpu_sample(&cpu_prev) != 0) {
        fprintf(stderr, "Failed to read /proc/stat\n");
=======
    // eBPF 초기화
    xtop_bpf_ctx_t *bpf_ctx = NULL;
    int bpf_ok = 0;

    if (geteuid() == 0) {
        if (xtop_bpf_init(&bpf_ctx, verbose_bpf ? true : false) == 0) {
            bpf_ok = 1;
        } else {
            bpf_ok = 0;
            bpf_ctx = NULL;
        }
    }

    // 초기 스냅샷
    if (read_cpu_sample(&cpu_prev) != 0) {
        fprintf(stderr, "Failed to read /proc/stat\n");
        xtop_bpf_destroy(bpf_ctx);
>>>>>>> 6e7074a (ebpf 초기 코드)
        return 1;
    }
    if (read_meminfo(&mi) != 0) {
        fprintf(stderr, "Failed to read /proc/meminfo\n");
<<<<<<< HEAD
=======
        xtop_bpf_destroy(bpf_ctx);
>>>>>>> 6e7074a (ebpf 초기 코드)
        return 1;
    }
    if (scan_processes(&prev, opt.only_pid) != 0) {
        fprintf(stderr, "Failed to scan /proc\n");
<<<<<<< HEAD
=======
        xtop_bpf_destroy(bpf_ctx);
>>>>>>> 6e7074a (ebpf 초기 코드)
        return 1;
    }

    int iter = 0;
    for (;;) {
        sleep_sec(opt.delay_sec);

<<<<<<< HEAD
=======
        // eBPF 스냅샷
        xtop_bpf_stats_t bst;
        memset(&bst, 0, sizeof(bst));
        if (bpf_ok) {
            if (xtop_bpf_snapshot(bpf_ctx, opt.delay_sec, ncpu, &bst) != 0) {
                bpf_ok = 0;
            }
        }

>>>>>>> 6e7074a (ebpf 초기 코드)
        if (read_cpu_sample(&cpu_cur) != 0) break;
        if (read_meminfo(&mi) != 0) break;

        proc_list_free(&cur);
        if (scan_processes(&cur, opt.only_pid) != 0) break;

        calc_cpu_usage(&cpu_prev, &cpu_cur, &usage_cpu);
        uint64_t cpu_total_delta = (cpu_cur.total >= cpu_prev.total) ? (cpu_cur.total - cpu_prev.total) : 0;

        compute_process_metrics(&cur, &prev, cpu_total_delta, ncpu, mi.mem_total_kb, page_size);
        sort_processes(&cur, opt.order);

        task_counts_t tc = count_tasks(&cur);

        clear_screen_if_needed(opt.batch);
        print_header(&usage_cpu, &mi, &tc, opt.batch);
<<<<<<< HEAD
=======

        // ATTACK line
        if (bpf_ok) {
            // 첫 샘플은 0.0이 나올 수 있음
            printf("ATTACK: NET_RX softirq %.1f%% | RUNQ p95 %.2f ms\n",
                   bst.net_rx_softirq_pct,
                   bst.runq_p95_ms);
        } else {
            if (geteuid() == 0) {
                printf("ATTACK: eBPF disabled (attach/load failed)\n");
            } else {
                printf("ATTACK: eBPF disabled (run as root)\n");
            }
        }

>>>>>>> 6e7074a (ebpf 초기 코드)
        print_table(&cur, opt.top_n, opt.batch, clk_tck);

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
<<<<<<< HEAD
=======

    xtop_bpf_destroy(bpf_ctx);
>>>>>>> 6e7074a (ebpf 초기 코드)
    return 0;
}
