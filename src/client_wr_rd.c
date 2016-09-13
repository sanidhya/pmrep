#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <pthread.h>

#include "rep_substrate.h"
#include "util.h"

#define BUFFER_SIZE (1ULL << 32)
#define BUFFER_GAP  (1ULL << 6)

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

pmrep_ctx_t pctx;
struct cmd_opt opt = {"192.168.0.1", 0, 0, 1000, 0, 0};

static inline void poll_send_cq(pmrep_ctx_t *pctx, uint64_t id, int thread_id)
{
    int n = 0;
    char correct_msg[L1D_CACHELINE_BYTES], wrong_msg[L1D_CACHELINE_BYTES];
    struct ibv_wc wc = { };

    do {
        n = ibv_poll_cq(pctx->rcm.send_cq, 1, &wc);
        dprintf("thread: %d, looping for id: %lu\n", thread_id, id);
    } while (n == 0);

    if (wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "Persist: expected: %s, got: %s\n",
                get_wr_status_name(IBV_WC_SUCCESS,
                                   correct_msg, L1D_CACHELINE_BYTES),
                get_wr_status_name(wc.status,
                                   wrong_msg, L1D_CACHELINE_BYTES));
        assert(0);

    }
    assert(wc.wr_id <= pctx->total_flush_wrs + pctx->total_persist_wrs);
    dprintf("thread: %d wc.wr_id: %lu id: %lu\n", thread_id, wc.wr_id, id);
    pctx->persist_cq_bits[wc.wr_id] = 1;
    smp_wmb();

    while (pctx->persist_cq_bits[id] == 0) {
        smp_rmb();
    }
}

static void inline update_sge(struct ibv_sge *sge, uint64_t addr,
                              uint32_t length, uint32_t lkey)
{
    sge->addr = addr;
    sge->length = length;
    sge->lkey = lkey;
}

static inline void update_send_wr(struct ibv_send_wr *wr, struct ibv_sge *sge,
                                  int opcode, int send_flags,
                                  uint64_t raddr, uint32_t rkey)
{
    wr->opcode = opcode;
    wr->next = NULL;
    wr->sg_list = sge;
    wr->num_sge = 1;
    if (send_flags == IBV_SEND_SIGNALED)
        wr->send_flags = send_flags;
    if (opcode == IBV_WR_RDMA_WRITE ||
        opcode == IBV_WR_RDMA_WRITE_WITH_IMM ||
        opcode == IBV_WR_RDMA_READ) {
        wr->wr.rdma.remote_addr = raddr;
        wr->wr.rdma.rkey = rkey;
    }
#if 0
    if ((opcode == IBV_WR_RDMA_WRITE ||
        opcode == IBV_WR_RDMA_WRITE_WITH_IMM ||
        opcode == IBV_WR_SEND) &&
        sge->length <= MAX_INLINE_DATA)
        wr->send_flags |= IBV_SEND_INLINE;
#endif
}

static inline void flush_data_remote(pmrep_ctx_t *pctx, uint8_t *buffer,
                                     size_t size, int n, int thread_id)
{
    struct thread_block *tblock = &pctx->thread_blocks[thread_id];
    struct buf_metainfo *minfo = &tblock->flush_bufinfo;
    struct swr_list_info *swr_node =
        &pctx->persist_wrnodes[thread_id * pctx->pt_flush_wrs + n];
    struct ibv_send_wr *wr = &swr_node->wr;
    struct ibv_sge *sge = &swr_node->sge;
    off_t offset = (uintptr_t)buffer - (uintptr_t)minfo->buffer;
    int ret = 0;

    update_sge(sge, (uintptr_t)buffer, size, minfo->mr->lkey);
    update_send_wr(wr, sge, IBV_WR_RDMA_WRITE, 0,
                   minfo->remote_data->buf_va + offset,
                   minfo->remote_data->buf_rkey);
    ret = ibv_post_send(pctx->rcm.qp, wr, &swr_node->bad_wr);
    assert(ret == 0);
    assert(swr_node->bad_wr == NULL);
}

static inline void persist_data_remote(pmrep_ctx_t *pctx, int thread_id)
{
    struct thread_block *tblock = &pctx->thread_blocks[thread_id];
    struct buf_metainfo *minfo = &tblock->read_bufinfo;
    struct swr_list_info *swr_node = &pctx->persist_wrnodes[thread_id *
                                  pctx->pt_persist_wrs + pctx->total_flush_wrs];
    struct ibv_send_wr *wr = &swr_node->wr;
    struct ibv_sge *sge = &swr_node->sge;
    int ret = 0;

    update_sge(sge, (uintptr_t)minfo->buffer, sizeof(int),
               minfo->mr->lkey);
    update_send_wr(wr, sge, IBV_WR_RDMA_READ, IBV_SEND_SIGNALED,
                   minfo->remote_data->buf_va,
                   minfo->remote_data->buf_rkey);

    ret = ibv_post_send(pctx->rcm.qp, wr, &swr_node->bad_wr);
    assert(ret == 0);
    assert(swr_node->bad_wr == NULL);

    poll_send_cq(pctx, wr->wr_id, thread_id);
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
            //start += L1D_CACHELINE_BYTES;
            //start += PAGE_SIZE;
            if (start >= eindex)
                start = sindex;
            if (start + opt.buffer_size > eindex)
                start -= (opt.buffer_size + 1);
            buf[start] = (count++ + 48)%10;
            flush_data_simple(&pctx, buf + start, opt.buffer_size, j, tid);
            //burn_cycles(opt.flush_latency);
        }
        persist_data_wread(&pctx, tid);
        //burn_cycles(opt.commit_latency);
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

    setup_region_client(&pctx, buf, BUFFER_SIZE, opt.num_threads, 1);

    if (opt.write_batch_count == 0)
        opt.write_batch_count = 1;

    opt.enable_lazy_writes = 0;

    for (i = 1; i < opt.num_threads; ++i) {
        assert(pthread_create(&th, NULL, run_bench, (void *)(intptr_t)i) == 0);
        while (!sync_state->cpu[i].ready)
            smp_rmb();
    }

    run_bench((void *)(intptr_t)0);
    waitup();

    return 0;
}
