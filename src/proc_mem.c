#include <stdio.h>
#include <string.h>
#include "proc_mem.h"

int read_meminfo(meminfo_t *out) {
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
