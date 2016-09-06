#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <string.h>
#include <signal.h>

#include "rep_substrate.h"
#include "util.h"

static pmrep_ctx_t pctx;

void handler(int sig)
{
    clear_region(&pctx, 1);
    exit(0);
}

static inline void poll_cq(struct ibv_cq *cq)
{
    int n = 0;
    struct ibv_wc wc = { };

    do {
        n = ibv_poll_cq(cq, 1, &wc);
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

static inline void update_send_wr(struct ibv_send_wr *wr, int opcode)
{
    wr->opcode = opcode;
    wr->send_flags = IBV_SEND_SIGNALED;
    wr->next = NULL;
    wr->sg_list = NULL;
    wr->num_sge = 0;
}

static inline void update_recv_wr(struct ibv_recv_wr *wr,
                                  struct ibv_sge *sge)
{
    wr->sg_list = sge;
    wr->num_sge = 1;
    wr->next = NULL;
}

static inline void ack_active_node(pmrep_ctx_t *pctx)
{
    struct swr_list_info *swr_node = &pctx->send_wrnodes[RDMA_SEND_WR_SID];
    struct rwr_list_info *rwr_node = &pctx->recv_wrnodes[0];
    struct ibv_send_wr *swr = &swr_node->wr;
    struct ibv_recv_wr *rwr = &rwr_node->wr;
    struct ibv_sge *rsge = &swr_node->sge;
    int ret = 0;

    update_send_wr(swr, IBV_WR_SEND_WITH_IMM);

    ret = ibv_post_send(pctx->rcm.qp, swr, &swr_node->bad_wr);
    assert(ret == 0);
    assert(swr_node->bad_wr == NULL);

    if (pctx->recv_posted_count <  MAX_POST_RECVS / 2) {
        update_sge(rsge, (uintptr_t)pctx->recv_bufinfo.buffer,
                   pctx->recv_bufinfo.size, pctx->recv_bufinfo.mr->lkey);
        update_recv_wr(rwr, rsge);

        poll_cq(pctx->rcm.send_cq);

        ret = ibv_post_recv(pctx->rcm.qp, rwr, &rwr_node->bad_wr);
        assert(ret == 0);
        assert(rwr_node->bad_wr == NULL);
        pctx->recv_posted_count++;
    }
}

static inline void handle_persistence(pmrep_ctx_t *pctx)
{
}

int main(int argc, char *argv[])
{
    struct cmd_opt opt = {"192.168.0.1", 0, 0, 1000, 0, 0};


    if (parse_options(argc, argv, &opt) < 0) {
        usage(stderr, argv[0]);
        return -1;
    }

    signal(SIGINT, handler);

    memset(&pctx, 0, sizeof(pctx));
    setup_region_server(&pctx);

    while (1) {

        poll_cq(pctx.rcm.recv_cq);
        pctx.recv_posted_count--;

        handle_persistence(&pctx);

        ack_active_node(&pctx);
    }

    return 0;
}
