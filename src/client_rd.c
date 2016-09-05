#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <string.h>

#include "rep_substrate.h"
#include "util.h"

#define BUFFER_SIZE (1ULL << 32)
#define BUFFER_GAP  (1ULL << 10)

int main(int argc, char *argv[])
{
    uint8_t *buf = mem_alloc_pgalign(BUFFER_SIZE, "Write buffer");
    int i = 0;
    double v = 0;
    uint64_t rd_t = 0, wr_t = 0;
    pmrep_ctx_t pctx = {};

    struct timespec start_t, mid_t, end_t;
    struct cmd_opt opt = {"192.168.0.1", 0, 0, 1000, 0, 0};

    if (parse_options(argc, argv, &opt) < 1) {
        usage(stderr, argv[0]);
        return -1;
    }

    if (!opt.buffer_size) {
        printf("setting buffer size to 8\n");
        opt.buffer_size = 8;
    }

    setup_region_client(&pctx, buf, BUFFER_SIZE);

    if (opt.write_batch_count == 0)
        opt.write_batch_count = 1;

    int count = 0;
    for (i = 0; i < opt.iterations; i++) {
        size_t j = 0, ptr = 0;
        clock_gettime(CLOCK_MONOTONIC, &start_t);
        for (j = 0; j < opt.write_batch_count; ++j) {
            buf[(i + j * BUFFER_GAP) % BUFFER_SIZE] = (count++ + 48)%10;
            ptr = (i * j * BUFFER_GAP) % BUFFER_SIZE;
            if (ptr + opt.buffer_size >= BUFFER_SIZE)
                ptr -= opt.buffer_size + 1;
            flush_data_simple(&pctx, buf + ptr,
                              opt.buffer_size, opt.enable_lazy_writes);
        }
        clock_gettime(CLOCK_MONOTONIC, &mid_t);
        persist_data_wread(&pctx);
        clock_gettime(CLOCK_MONOTONIC, &end_t);
        wr_t += get_time_diff(start_t, mid_t);
        rd_t += get_time_diff(mid_t, end_t);
    }

    printf("batch: %d, iterations: %d\n", opt.write_batch_count, opt.iterations);
    printf("%s: avg write time: %lf\n", opt.enable_lazy_writes?"lazy":"eager",
           (double)wr_t / (double)(opt.iterations * opt.write_batch_count));

    printf("avg persist time: %lf\n", (double)rd_t / (double)(opt.iterations));

    v = (double)wr_t / (double)(opt.iterations * opt.write_batch_count);
    v += ((double)rd_t / (double)(opt.iterations));

    printf("avg total time: %lf\n", v);
    printf("total time: %lf sec\n", (double)(wr_t + rd_t)/1000000000.0);
    return 0;
}
