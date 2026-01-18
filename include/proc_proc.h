#ifndef PROC_PROC_H
#define PROC_PROC_H

#include <stddef.h>
#include <stdint.h>
#include "xtop.h"

typedef struct {
    proc_entry_t *items;
    size_t len;
    size_t cap;
} proc_list_t;

void proc_list_free(proc_list_t *pl);

// /proc 전체 스캔
int scan_processes(proc_list_t *out, pid_t only_pid);

// 프로세스 메트릭 계산
void compute_process_metrics(proc_list_t *cur,
                             const proc_list_t *prev,
                             uint64_t cpu_total_delta_ticks,
                             int ncpu,
                             uint64_t mem_total_kb,
                             long page_size);

// 정렬
int sort_processes(proc_list_t *pl, xtop_order_t order);

// Tasks 상태 카운트
task_counts_t count_tasks(const proc_list_t *pl);

#endif
