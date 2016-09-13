#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include "rep_substrate.h"
#include "util.h"

#define BUFFER_SIZE (1ULL << 32)
#define BUFFER_GAP  (1ULL << 6)

static struct {
   volatile int start;
   volatile int stop;
   union {
	struct {
	    volatile int ready;
	    volatile uint64_t jobs;
        volatile double tput;
	};
	char pad[L1D_CACHELINE_BYTES];
   } cpu[MAX_CPU] ____cacheline_aligned;
} *sync_state;

//pmrep_ctx_t pctx;
struct cmd_opt opt = {"192.168.0.1", 0, 0, 1000, 0, 0};
uint8_t *buf;

static void sighandler(int i)
{
    sync_state->stop = 1;
}

void *run_bench(void *arg)
{
    int tid = (uintptr_t)arg;
    uint64_t i = 0;
    int count = 0;
    size_t block_size = BUFFER_SIZE / opt.num_threads;
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

    while (!sync_state->stop) {
        size_t j = 0;
        for (j = 0; j < opt.write_batch_count; ++j) {
            if (start >= eindex)
                start = sindex;
            if (start + opt.buffer_size > eindex)
                start -= (opt.buffer_size + 1);
            buf[start] = (count++ + 48)%10;
            //flush_data_simple(&pctx, buf + start, opt.buffer_size, j, tid);
            clflushopt_overhead(opt.buffer_size);
            burn_cycles(opt.flush_latency);
        }
        burn_cycles(opt.commit_latency);
        //persist_data_wread(&pctx, tid);
        smp_wmb();
        msync_overhead();
        ++i;
    }

    sync_state->cpu[tid].jobs = i;
    return NULL;
}

static void waitup(void)
{
    uint64_t tot, max;
	int i;
	double avg = 0.0;

	tot = 0;
	max = 0;
	for (i = 0; i < opt.num_threads; i++) {
		while (!sync_state->cpu[i].jobs)
			nop_pause();

		tot += sync_state->cpu[i].jobs;
		if (sync_state->cpu[i].jobs > max)
			max = sync_state->cpu[i].jobs;
		avg += (double)sync_state->cpu[i].jobs;
	}

    avg /= (double)opt.duration;
    avg /= (double)opt.num_threads;

	printf("threads: %d size: %ld duration: %d jobs: %.3lf (#jobs/sec/core)\n",
	       opt.num_threads, opt.buffer_size, opt.duration, avg);
}

int main(int argc, char *argv[])
{
    int i = 0;
    pthread_t th;

    buf = mem_alloc_pgalign(BUFFER_SIZE, "Write buffer");
    sync_state = mem_alloc_pgalign(sizeof(*sync_state), "Sync state");

    if (parse_options(argc, argv, &opt) < 2) {
        usage(stderr, argv[0]);
        return -1;
    }

    if (!opt.buffer_size) {
        opt.buffer_size = 8;
    }

    //setup_region_client(&pctx, buf, BUFFER_SIZE, opt.num_threads, 1);

    if (opt.write_batch_count == 0)
        opt.write_batch_count = 1;

    if (!opt.duration)
        opt.duration = 30;

    if (signal(SIGALRM, sighandler) == SIG_ERR){
        fprintf(stderr, "cannot set sig alarm\n");
        assert(0);
    }
    alarm(opt.duration);

    for (i = 1; i < opt.num_threads; ++i) {
        assert(pthread_create(&th, NULL, run_bench, (void *)(intptr_t)i) == 0);
        while (!sync_state->cpu[i].ready)
            smp_rmb();
    }

    run_bench((void *)(intptr_t)0);
    waitup();

    return 0;
}
