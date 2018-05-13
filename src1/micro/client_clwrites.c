#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <pthread.h>

#include "rdma_substrate.h"
#include "util.h"

#define BUFFER_SIZE (40960)

static struct {
    volatile int start;
    union {
        struct {
            volatile int ready;
            volatile uint64_t latency;
            volatile double tput;
        };
        char pad[L1D_CACHELINE_BYTES];
    } cpu[MAX_CPU] ____cacheline_aligned;
} *sync_state;

rep_ctx_t pctx;
struct cmd_opt opt = {
    .server_ip = "192.168.0.1",
    .tcp_conn_port = 0,
    .num_threads = 1,
    .iterations = 1000,
    .allow_inlined_data = 0,
    .write_batch_count = 0,
    .enable_lazy_writes = 0,
    .const_cores = 0,
    .duration = 0
};

static void inline update_sge(struct ibv_sge *sge, uint64_t addr,
                              uint32_t length, uint32_t lkey)
{
    sge->addr = addr;
    sge->length = length;
    sge->lkey = lkey;
}

void *run_bench(void *arg)
{
    int tid = (uintptr_t)arg;
    uint64_t i;
    struct timespec start_t, end_t;
    uint8_t *buf = pctx.common_buffer;
    int count = 0;
    size_t block_size = BUFFER_SIZE / pctx.num_threads;
    size_t sindex = tid * block_size;
    size_t eindex = (tid + 1) * block_size;
    size_t start = sindex;

    setaffinity(tid + opt.const_cores);
    sync_state->cpu[tid].ready = 1;

    if (tid)
        while (!sync_state->start)
            nop_pause();
    else
        sync_state->start = 1;

    clock_gettime(CLOCK_MONOTONIC, &start_t);
    for (i = 0; i < opt.iterations; i++) {
        size_t j = 0;
        for (j = 0; j < opt.write_batch_count; ++j) {
            if (start >= eindex)
                start = sindex;
            if (start + opt.buffer_size > eindex)
                start -= (opt.buffer_size + 1);
            buf[start] = (count++ + 48)%10;
            flush_data_simple(&pctx, buf + start, opt.buffer_size, j, tid);
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end_t);

    sync_state->cpu[tid].latency = get_time_diff(start_t, end_t);
    return NULL;
}

static void waitup(void)
{
    uint64_t tot, max;
    int i;
    double avg = 0.0;

    tot = 0;
    max = 0;
    for (i = 0; i < pctx.num_threads; i++) {
        while (!sync_state->cpu[i].latency)
            nop_pause();

        tot += sync_state->cpu[i].latency;
        if (sync_state->cpu[i].latency > max)
            max = sync_state->cpu[i].latency;
        avg += (double)sync_state->cpu[i].latency;
    }

    avg /= (double)opt.iterations;
    avg /= (double)pctx.num_threads;
    avg /= 1000.0;

    printf("threads: %d iterations: %d avg-latency: %.3lf\n",
           pctx.num_threads, opt.iterations, avg);
}

int main(int argc, char *argv[])
{
    uint8_t *buf = mem_alloc_pgalign(BUFFER_SIZE, "Write buffer");
    int i = 0;
    pthread_t th;

    sync_state = mem_alloc_pgalign(sizeof(*sync_state), "Sync state");


    if (parse_options(argc, argv, &opt) < 2) {
        usage(stderr, argv[0]);
        return -1;
    }

    if (!opt.buffer_size) {
        printf("setting buffer size to 8\n");
        opt.buffer_size = 8;
    }

    printf("num threads: %d\n", pctx.num_threads);
    setup_region_client(&pctx, buf, BUFFER_SIZE, opt.num_threads);

    if (opt.write_batch_count == 0)
        opt.write_batch_count = 1;

    opt.enable_lazy_writes = 0;

    for (i = 1; i < opt.num_threads; ++i) {
        dassert(pthread_create(&th, NULL, run_bench, (void *)(intptr_t)i) == 0);
        while (!sync_state->cpu[i].ready)
            smp_rmb();
    }

    run_bench((void *)(intptr_t)0);
    waitup();

    return 0;
}
