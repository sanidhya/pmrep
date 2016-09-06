#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>

#include "rep_substrate.h"
#include "util.h"

#define BUFFER_SIZE (1ULL << 32)
#define BUFFER_GAP  (1ULL << 10)

static inline void poll_send_cq(pmrep_ctx_t *pctx)
{
    int n = 0;
    struct ibv_wc wc = { };

    do {
        n = ibv_poll_cq(pctx->rcm.send_cq, 1, &wc);
    } while (n == 0);

    assert(wc.status == IBV_WC_SUCCESS);
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
    if ((opcode == IBV_WR_RDMA_WRITE ||
        opcode == IBV_WR_RDMA_WRITE_WITH_IMM ||
        opcode == IBV_WR_SEND) &&
        sge->length <= MAX_INLINE_DATA)
        wr->send_flags |= IBV_SEND_INLINE;
}

static inline void flush_data_remote(pmrep_ctx_t *pctx,
                                     uint8_t *buffer, size_t size, int n)
{
    struct swr_list_info *swr_node = &pctx->send_wrnodes[n + RDMA_WRITE_WR_SID];
    struct ibv_send_wr *wr = &swr_node->wr;
    struct ibv_sge *sge = &swr_node->sge;
    off_t offset = (uintptr_t)buffer - (uintptr_t)pctx->write_bufinfo.buffer;
    int ret = 0;

    update_sge(sge, (uintptr_t)buffer, size, pctx->write_bufinfo.mr->lkey);
    update_send_wr(wr, sge, IBV_WR_RDMA_WRITE, 0,
                   pctx->remote_data[0].buf_va + offset,
                   pctx->remote_data[0].buf_rkey);
    ret = ibv_post_send(pctx->rcm.qp, wr, &swr_node->bad_wr);
    assert(ret == 0);
    assert(swr_node->bad_wr == NULL);
}

static inline void persist_data_remote(pmrep_ctx_t *pctx)
{
    struct swr_list_info *swr_node = &pctx->send_wrnodes[RDMA_READ_WR_SID];
    struct ibv_send_wr *wr = &swr_node->wr;
    struct ibv_sge *sge = &swr_node->sge;
    int ret = 0;

    update_sge(sge, (uintptr_t)pctx->read_bufinfo.buffer, sizeof(int),
               pctx->read_bufinfo.mr->lkey);
    update_send_wr(wr, sge, IBV_WR_RDMA_READ, IBV_SEND_SIGNALED,
                   pctx->remote_data[1].buf_va,
                   pctx->remote_data[1].buf_rkey);

    ret = ibv_post_send(pctx->rcm.qp, wr, &swr_node->bad_wr);
    assert(ret == 0);
    assert(swr_node->bad_wr == NULL);

    poll_send_cq(pctx);
}

int main(int argc, char *argv[])
{
    uint8_t *buf = mem_alloc_pgalign(BUFFER_SIZE, "Write buffer");
    int i = 0;
    double v = 0;
    uint64_t rd_t = 0, wr_t = 0;
    uint64_t count = 0;
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

    opt.enable_lazy_writes = 0;

    for (i = 0; i < opt.iterations; i++) {
        size_t j = 0, ptr = 0;
        clock_gettime(CLOCK_MONOTONIC, &start_t);
        for (j = 0; j < opt.write_batch_count; ++j) {
            buf[(i + j * BUFFER_GAP) % BUFFER_SIZE] = (count++ + 48)%10;
            ptr = (i * j * BUFFER_GAP) % BUFFER_SIZE;
            if (ptr + opt.buffer_size >= BUFFER_SIZE)
                ptr -= opt.buffer_size + 1;
            flush_data_remote(&pctx, buf + ptr, opt.buffer_size, j);
        }
        clock_gettime(CLOCK_MONOTONIC, &mid_t);
        persist_data_remote(&pctx);
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

