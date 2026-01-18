#ifndef FMT_H
#define FMT_H

#include <stdbool.h>
#include "xtop.h"
#include "proc_proc.h"

void clear_screen_if_needed(bool batch);
void print_header(const cpu_usage_t *cu, const meminfo_t *mi, const task_counts_t *tc, bool batch);
void print_table(const proc_list_t *pl, int top_n, bool batch, long clk_tck);

#endif
