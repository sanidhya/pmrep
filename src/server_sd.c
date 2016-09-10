#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <sys/mman.h>

#include "rep_substrate.h"
#include "util.h"

static pmrep_ctx_t pctx;
int stop_flag = 0;

void handler(int sig)
{
    stop_flag = 1;
    clear_region(&pctx, 1);
    exit(0);
}

struct cmd_opt opt = {"192.168.0.1", 0, 0, 1000, 0, 0};

static inline struct rwr_list_info *get_rnode(struct rwr_list_info *nodes,
                                              uint64_t id, uint64_t num_elems)
{
    uint64_t i;

    /* XXX: replace with binary search even though the list is small */
    for (i = 0; i < num_elems; ++i) {
        if (id == nodes[i].wr.wr_id)
            return &nodes[i];
    }
    /* XXX: this should never happen */
    assert(0);
    return NULL;
}

static inline struct rwr_list_info *poll_recv_cq_server(pmrep_ctx_t *pctx,
                                                        int thread_id)
{
    char correct_msg[L1D_CACHELINE_BYTES], wrong_msg[L1D_CACHELINE_BYTES];
    struct ibv_wc wc = { };
    int n = 0;

    do {
        n = ibv_poll_cq(pctx->rcm.recv_cq, 1, &wc);
        dprintf("thread: %d, looping for id: %lu\n", thread_id, wc.wr_id);
    } while (n == 0);

    if (wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "Persist: expected: %s, got: %s\n",
                get_wr_status_name(IBV_WC_SUCCESS,
                                   correct_msg, L1D_CACHELINE_BYTES),
                get_wr_status_name(wc.status,
                                   wrong_msg, L1D_CACHELINE_BYTES));
        assert(0);

    }

    assert(wc.wr_id >= pctx->total_flush_wrs + pctx->total_persist_wrs);
    dprintf("thread: %d id: %lu\n", thread_id, wc.wr_id);
    return get_rnode(pctx->recv_bufinfo.recv_wrnodes, wc.wr_id,
                     pctx->total_recv_wrs);
}

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

static inline void free_persist_lists(pmrep_ctx_t *pctx, uint64_t id,
                                      int thread_id)
{
    struct swr_list_info *send_node = &pctx->persist_wrnodes[id];
    struct thread_block *tblock = &pctx->thread_blocks[thread_id];
    struct buf_metainfo *minfo = &tblock->persist_bufinfo;

    pctx->persist_cq_bits[id] = 0;
    smp_wmb();
    list_move(&send_node->node, &minfo->free_lhead);
}

static inline void update_send_wr(struct ibv_send_wr *wr, struct ibv_sge *sge,
                                  int opcode, int send_flags,
                                  uint64_t raddr, uint32_t rkey)
{
    /* XXX: optimize this one as we need to only send one piece of data */
    wr->opcode = opcode;
    wr->next = NULL;
    wr->sg_list = sge;
    wr->num_sge = sge?1:0;
    if (send_flags == IBV_SEND_SIGNALED)
        wr->send_flags = send_flags;
    if (opcode == IBV_WR_RDMA_WRITE ||
        opcode == IBV_WR_RDMA_WRITE_WITH_IMM ||
        opcode == IBV_WR_RDMA_READ) {
        wr->wr.rdma.remote_addr = raddr;
        wr->wr.rdma.rkey = rkey;
    }
    if ((opcode == IBV_WR_RDMA_WRITE ||
        opcode == IBV_WR_RDMA_WRITE_WITH_IMM) &&
        sge->length <= MAX_INLINE_DATA)
        wr->send_flags |= IBV_SEND_INLINE;
}

static inline void get_and_post_recv_wr(pmrep_ctx_t *pctx,
                                        struct rwr_list_info *rwr_node,
                                        uint64_t sid)
{
    int ret;

    pctx->recv_cq_bits[sid] = 0;
    ret = ibv_post_recv(pctx->rcm.qp, &rwr_node->wr, &rwr_node->bad_wr);
    assert(ret == 0);
    assert(rwr_node->bad_wr == NULL);
}

static inline void ack_active_node(pmrep_ctx_t *pctx,
                                   struct rwr_list_info *rwr_node, uint64_t id,
                                   int thread_id)
{
    struct thread_block *tblock = &pctx->thread_blocks[thread_id];
    struct buf_metainfo *minfo = &tblock->persist_bufinfo;
    struct swr_list_info *pos, *tmp;
    struct ibv_send_wr *wr = NULL;
    int ret = 0;

    list_for_each_entry_safe(pos, tmp, &minfo->free_lhead, node) {
        list_move_tail(&pos->node, &minfo->busy_lhead);
        break;
    }

    wr = &pos->wr;
    update_send_wr(wr, NULL, IBV_WR_SEND_WITH_IMM, IBV_SEND_SIGNALED, NOVALUE,
                                                                       NOVALUE);
    wr->imm_data = id;
    ret = ibv_post_send(pctx->rcm.qp, wr, &pos->bad_wr);
    assert(ret == 0);
    assert(pos->bad_wr == NULL);
    poll_send_cq(pctx, wr->wr_id, thread_id);
    free_persist_lists(pctx, wr->wr_id, thread_id);
    get_and_post_recv_wr(pctx, rwr_node, wr->wr_id);
}

static inline void handle_persistence(struct pdlist *pdlist)
{
    uint32_t elems = pdlist->elems;
    persistence_t pt = pdlist->pt;
    uint32_t i;

    switch(pt) {
    case NO_PERSISTENCE_DDIO:
    case NO_PERSISTENCE_NODDIO:
    case WEAK_PERSISTENCE_WITH_ADR_NODDIO:
    case WEAK_PERSISTENCE_WITH_eADR_DDIO:
    case WEAK_PERSISTENCE_WITH_eADR_NODDIO:
        break;
    case WEAK_PERSISTENCE_WITH_ADR_DDIO:
        for (i = 0; i < elems; ++i)
            clflush_range((void *)pdlist->list[i].ptr, pdlist->list[i].len);
        break;
    case STRONG_PERSISTENCE_WITH_ADR_DDIO:
    case STRONG_PERSISTENCE_WITH_eADR_DDIO:
        for (i = 0; i < elems; ++i) {
            clflush_range((void *)pdlist->list[i].ptr, pdlist->list[i].len);
            msync((void *)(uintptr_t)pdlist->list[i].ptr, pdlist->list[i].len,
                  MS_SYNC);
        }
        break;
    case STRONG_PERSISTENCE_WITH_ADR_NODDIO:
    case STRONG_PERSISTENCE_WITH_eADR_NODDIO:
        for (i = 0; i < elems; ++i) {
            msync((void *)(uintptr_t)pdlist->list[i].ptr, pdlist->list[i].len,
                  MS_SYNC);
        }
        break;
    default:
        assert(0);
    }
}

void *handle_req(void *arg)
{
    int tid = (uintptr_t)arg;
    struct rwr_list_info *rwr_node = NULL;
    struct pdlist *pdlist = NULL;
    setaffinity(opt.const_cores + tid);

    while (stop_flag == 0) {

        rwr_node = poll_recv_cq_server(&pctx, tid);
        pdlist = (struct pdlist *)(uintptr_t)rwr_node->sge.addr;
        handle_persistence(pdlist);
        ack_active_node(&pctx, rwr_node, pdlist->wr_id, tid);

    }
    return NULL;
}

int main(int argc, char *argv[])
{
    int i = 0;
    pthread_t th;
    int max_cores = 1;

    if (parse_options(argc, argv, &opt) < 1) {
        usage(stderr, argv[0]);
        return -1;
    }

    memset(&pctx, 0, sizeof(pctx));

    signal(SIGINT, handler);
    setup_region_server(&pctx);

    if (opt.max_cores <= 0)
        max_cores = pctx.num_threads;
    else if (opt.max_cores <= pctx.num_threads)
        max_cores = opt.max_cores;

    for (i = 1; i < max_cores; ++i) {
        assert(pthread_create(&th, NULL, handle_req, (void *)(intptr_t)i) == 0);
    }

    handle_req((void *)(intptr_t)0);
    return 0;
}
