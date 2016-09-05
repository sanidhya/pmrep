#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "rep_substrate.h"
#include "util.h"

#ifdef DPRINT
#define print_used_minfo_list(__list) _print_used_minfo_list(__list)

static inline void _print_used_minfo_list(struct list_head *head)
{
    struct swr_list_info *pos;
    dprintf("--- id: ");
    list_for_each_entry(pos, head, node) {
        fprintf(stderr, "%lu ", pos->wr.wr_id);
    }
    fprintf(stderr, "---\n");
}
#else
#define print_used_minfo_list(__list) do { } while(0)
#endif



/*
 * taken freom qperf
 */
static struct error_name cq_errors[] = {
    { IBV_WC_SUCCESS,                   "Success"                       },
    { IBV_WC_LOC_LEN_ERR,               "Local length error"            },
    { IBV_WC_LOC_QP_OP_ERR,             "Local QP operation failure"    },
    { IBV_WC_LOC_EEC_OP_ERR,            "Local EEC operation failure"   },
    { IBV_WC_LOC_PROT_ERR,              "Local protection error"        },
    { IBV_WC_WR_FLUSH_ERR,              "WR flush failure"              },
    { IBV_WC_MW_BIND_ERR,               "Memory window bind failure"    },
    { IBV_WC_BAD_RESP_ERR,              "Bad response"                  },
    { IBV_WC_LOC_ACCESS_ERR,            "Local access failure"          },
    { IBV_WC_REM_INV_REQ_ERR,           "Remote invalid request"        },
    { IBV_WC_REM_ACCESS_ERR,            "Remote access failure"         },
    { IBV_WC_REM_OP_ERR,                "Remote operation failure"      },
    { IBV_WC_RETRY_EXC_ERR,             "Retries exceeded"              },
    { IBV_WC_RNR_RETRY_EXC_ERR,         "RNR retry exceeded"            },
    { IBV_WC_LOC_RDD_VIOL_ERR,          "Local RDD violation"           },
    { IBV_WC_REM_INV_RD_REQ_ERR,        "Remote invalid read request"   },
    { IBV_WC_REM_ABORT_ERR,             "Remote abort"                  },
    { IBV_WC_INV_EECN_ERR,              "Invalid EECN"                  },
    { IBV_WC_INV_EEC_STATE_ERR,         "Invalid EEC state"             },
    { IBV_WC_FATAL_ERR,                 "Fatal error"                   },
    { IBV_WC_RESP_TIMEOUT_ERR,          "Responder timeout"             },
    { IBV_WC_GENERAL_ERR,               "General error"                 },
};

static struct error_name cm_events[] = {
    { RDMA_CM_EVENT_ADDR_RESOLVED,      "Address resolved"              },
    { RDMA_CM_EVENT_ADDR_ERROR,         "Address error"                 },
    { RDMA_CM_EVENT_ROUTE_RESOLVED,     "Route resolved"                },
    { RDMA_CM_EVENT_ROUTE_ERROR,        "Route error"                   },
    { RDMA_CM_EVENT_CONNECT_REQUEST,    "Connect request"               },
    { RDMA_CM_EVENT_CONNECT_RESPONSE,   "Connect response"              },
    { RDMA_CM_EVENT_CONNECT_ERROR,      "Connect error"                 },
    { RDMA_CM_EVENT_UNREACHABLE,        "Event unreachable"             },
    { RDMA_CM_EVENT_REJECTED,           "Event rejected"                },
    { RDMA_CM_EVENT_ESTABLISHED,        "Event established"             },
    { RDMA_CM_EVENT_DISCONNECTED,       "Event disconnected"            },
    { RDMA_CM_EVENT_DEVICE_REMOVAL,     "Device removal"                },
    { RDMA_CM_EVENT_MULTICAST_JOIN,     "Multicast join"                },
    { RDMA_CM_EVENT_MULTICAST_ERROR,    "Multicast error"               },
};

static struct error_name persistence_type[] = {
    { NO_PERSISTENCE,       "NO PERSISTENCE (DEFAULT)"                  },
    { WEAK_PERSISTENCE,     "WEAK PERSISTENCE"                          },
    { STRONG_PERSISTENCE,   "STRONG PERSISTENCE"                        },
};

static inline char *get_value(int value, struct error_name *name_array,
                              char *data, size_t size)
{
    strncpy(data, name_array[value].name, size);
    data[size - 1] = '\0';
    return data;
}

static inline char *get_pt_name(persistence_t pt, char *data)
{
    return get_value(pt, persistence_type, data, L1D_CACHELINE_BYTES);
}

static inline char *get_wr_status_name(int status, char *data, size_t size)
{
    return get_value(status, cq_errors, data, size);
}

static inline char *get_cm_event_name(int event, char *data, size_t size)
{
    return get_value(event, cm_events, data, size);
}

static inline void poll_send_cq(pmrep_ctx_t *pctx, uint64_t id)
{
    struct ibv_wc wc = {};
    char correct_msg[L1D_CACHELINE_BYTES], wrong_msg[L1D_CACHELINE_BYTES];
    int n = 0;
    struct ibv_cq *cq = pctx->rcm.send_cq;
    uint8_t *bit_array = pctx->persist_cq_bits;

    dprintf("========= SEND POLL COUNT: %lu =========\n",
            ++pctx->stats.poll_send_count);
    dprintf("polling on send cq for wr id: %lu\n", id);
    do {
        n = ibv_poll_cq(cq, 1, &wc);
    } while (n == 0);

    if (n < 0) {
        fprintf(stderr, "failed to poll completions from the CQ: ret = %d", n);
        assert(0);
    }
    if (wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "SEND: expected: %s, got: %s\n",
                get_wr_status_name(IBV_WC_SUCCESS,
                                   correct_msg, L1D_CACHELINE_BYTES),
                get_wr_status_name(wc.status,
                                   wrong_msg, L1D_CACHELINE_BYTES));
        assert(0);
    }
    dprintf("got the send wr id: %lu with wc id: %lu\n", id, wc.wr_id);
    bit_array[wc.wr_id] = 1;
    smp_wmb();

    while (bit_array[id] != 1) {
        smp_rmb();
    }
    dprintf("persisted the data at the other end\n");
}

static inline uint64_t poll_recv_cq(pmrep_ctx_t *pctx, uint64_t id)
{
    /* XXX: fix me, this is still wrong !! */
    struct ibv_wc wc = {};
    char correct_msg[L1D_CACHELINE_BYTES], wrong_msg[L1D_CACHELINE_BYTES];
    int n = 0;
    struct ibv_cq *cq = pctx->rcm.recv_cq;
    uint64_t *wr_id = (uint64_t *)pctx->recv_bufinfo.buffer;
    /* this will be shared with the server side to write to it */
    uint8_t *bit_array = pctx->recv_cq_bits;

    dprintf("========= RECV POLL COUNT: %lu =========\n",
            ++pctx->stats.poll_recv_count);
    dprintf("polling on recv cq for wr id: %lu\n", id);
    do {
        n = ibv_poll_cq(cq, 1, &wc);
    } while (n == 0);
    if (wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "RECV: expected: %s, got: %s\n",
                get_wr_status_name(IBV_WC_SUCCESS,
                                   correct_msg, L1D_CACHELINE_BYTES),
                get_wr_status_name(wc.status,
                                   wrong_msg, L1D_CACHELINE_BYTES));
        assert(0);

    }
    dprintf("got the recv wr id: %lu with wc id: %lu\n",
            wr_id[0], wc.wr_id);
    bit_array[wr_id[0]] = 1;

    while (bit_array[wr_id[0]] != 1) {
        smp_rmb();
    }
    return wc.wr_id;
}

/* sge and wr update */
static void inline update_sge(struct ibv_sge *sge, uint64_t addr,
                              uint32_t length, uint32_t lkey)
{
    dprintf("updating sge for addr: %lx, of len: %u\n", addr, length);
    sge->addr = addr;
    sge->length = length;
    sge->lkey = lkey;
}

static inline void update_send_wr(struct ibv_send_wr *wr, struct ibv_sge *sge,
                                  int opcode, int send_flags,
                                  uint64_t raddr, uint32_t rkey)
{
    dprintf("update send wr with id: %lu\n", wr->wr_id);
    wr->opcode = opcode;
    if (send_flags == IBV_SEND_SIGNALED)
        wr->send_flags = send_flags;
    wr->sg_list = sge;
    wr->num_sge = 1;
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
    wr->next = NULL;
}

static inline void update_recv_wr(struct ibv_recv_wr *wr,
                                  struct ibv_sge *sge)
{
    dprintf("updating recv sge with wr id: %lu\n", wr->wr_id);
    wr->sg_list = sge;
    wr->num_sge = 1;
    wr->next = NULL;
}

static void post_recv_wr(pmrep_ctx_t *pctx, int num, size_t size)
{
    int ret = 0;
    int i;
    struct buf_metainfo *recv_minfo = &pctx->recv_bufinfo;
    struct mcsqnode_t qnode = {};

    for (i = 0; i < num; i++) {
        dprintf("========= POST RECV COUNT: %lu =========\n",
                ++pctx->stats.post_recv_count);
        /* get the entry from head->next of free_lhead_rwr */
        dprintf("acquire rwr_lock\n");
        spin_lock(&pctx->rwr_lock, &qnode);
        struct rwr_list_info *rwr_node = list_entry(pctx->free_lhead_rwr.next,
                                                    struct rwr_list_info, node);
        dprintf("got node with wr id: %lu\n", rwr_node->wr.wr_id);

        /* delete the entry from free list */
        list_move_tail(&rwr_node->node, &recv_minfo->wr_lhead);

        /* update the wr and sge respectively */
        struct ibv_recv_wr *wr = &rwr_node->wr;
        struct ibv_sge *sge = &rwr_node->sge;
        update_sge(sge, (uintptr_t)recv_minfo->buffer,
                   size, recv_minfo->mr->lkey);
        update_recv_wr(wr, sge);

        pctx->recv_posted_count++;
        dprintf("posted receive count: %lu\n", pctx->recv_posted_count);

        dprintf("release rwr_lock\n");
        spin_unlock(&pctx->rwr_lock, &qnode);

        dprintf("posting recv wr with id: %lu\n", wr->wr_id);
        ret = ibv_post_recv(pctx->rcm.qp, wr, &rwr_node->bad_wr);
        assert(ret == 0);
        assert(rwr_node->bad_wr == NULL);

    }
}

static inline void clean_wlist(pmrep_ctx_t *pctx)
{
    struct list_head *head = &pctx->write_bufinfo.wr_lhead;
    struct swr_list_info *pos, *tmp;
    uint64_t wr_size = sizeof(struct ibv_send_wr);
    uint64_t id = 0;

    dprintf("========= CLEAN WLIST COUNT: %lu =========\n",
            ++pctx->stats.clean_wlist_count);
    print_used_minfo_list(&pctx->write_bufinfo.wr_lhead);

    list_for_each_entry_safe(pos, tmp, head, node) {

        dprintf("removing entry with wr id: %lu\n", pos->wr.wr_id);
        if (!pctx->persist_wr_bits[pos->wr.wr_id]) {
            dprintf("the wr id (%lu) is yet to be posted\n", pos->wr.wr_id);
            break;
        }

        list_move_tail(&pos->node, &pctx->free_lhead_swr);
        id = pos->wr.wr_id;
        memset(&pos->wr, 0, wr_size);
        pos->wr.wr_id = id;
        pctx->persist_wr_bits[id] = 0;
        pctx->persist_cq_bits[id] = 0;
        dprintf("removed entry with wr id: %lu\n", id);
    }
}

static inline void clean_slist(pmrep_ctx_t *pctx,
                               struct swr_list_info *swr_node)
{
    struct mcsqnode_t qnode = {};
    uint64_t id = swr_node->wr.wr_id;

    memset(&swr_node->wr, 0, sizeof(swr_node->wr));
    dprintf("acquire swr_lock\n");
    spin_lock(&pctx->swr_lock, &qnode);
    dprintf("========= CLEAN SLIST COUNT: %lu =========\n",
            ++pctx->stats.clean_slist_count);

    clean_wlist(pctx);
    dprintf("deleting wr with wr id: %lu used for persistence\n",
            swr_node->wr.wr_id);

    swr_node->wr.wr_id = id;
    list_move_tail(&swr_node->node, &pctx->free_lhead_swr);

    pctx->persist_cq_bits[id] = 0;
    pctx->persist_wr_bits[id] = 0;

    dprintf("release swr_lock\n");
    spin_unlock(&pctx->swr_lock, &qnode);
}

static inline void clean_rlist(pmrep_ctx_t *pctx, uint64_t id)
{
    struct rwr_list_info *rwr_node = &pctx->recv_wrnodes[id];
    struct mcsqnode_t qnode = {};

    dprintf("========= CLEAN RLIST COUNT: %lu =========\n",
            ++pctx->stats.clean_rlist_count);
    dprintf("acquire rwr_lock\n");
    spin_lock(&pctx->rwr_lock, &qnode);

    list_move_tail(&rwr_node->node, &pctx->free_lhead_rwr);

    pctx->recv_cq_bits[id] = 0;
    pctx->recv_posted_count--;
    dprintf("current posted count: %lu\n", pctx->recv_posted_count);

    dprintf("release rwr_lock\n");
    spin_unlock(&pctx->rwr_lock, &qnode);
}

static inline int bulk_flush_data(pmrep_ctx_t *pctx)
{
    struct swr_list_info *pos, *head = NULL;
    struct ibv_send_wr *prev_wr = NULL, *cur_wr = NULL;
    struct mcsqnode_t qnode = {};
    int wr_count = 0;
    int ret = 0;

    dprintf("========= BULK FLUSH COUNT: %lu =========\n",
            ++pctx->stats.bulk_flush_count);
    spin_lock(&pctx->swr_lock, &qnode);
    dprintf("acquire swr_lock\n");

    if (list_empty(&pctx->write_bufinfo.wr_lhead)) {
        dprintf("there are no pending writes, returning back\n");
        spin_unlock(&pctx->swr_lock, &qnode);
        return 0;
    }

    list_for_each_entry(pos, &pctx->write_bufinfo.wr_lhead, node) {
        dprintf("wr node: %lu\n", pos->wr.wr_id);
        uint64_t id = pos->wr.wr_id;
        if (pctx->persist_wr_bits[id]) {
            dprintf("the wr (%lu) has been already posted\n", pos->wr.wr_id);
            break;
        }
        wr_count++;
        pctx->persist_wr_bits[id] = 1;
        if (!cur_wr)
            head = pos;
        if (prev_wr)
            prev_wr->next = cur_wr;
        prev_wr = cur_wr;
        cur_wr = &pos->wr;
    }
    if (!head) {
        spin_unlock(&pctx->swr_lock, &qnode);
        dprintf("release swr_lock\n");
        return 1;
    }
    if (prev_wr)
        prev_wr->next = cur_wr;
    dprintf("release swr_lock\n");
    spin_unlock(&pctx->swr_lock, &qnode);

    dprintf("posing the work requests for %d ids\n", wr_count);
    ret = ibv_post_send(pctx->rcm.qp, &head->wr, &head->bad_wr);
    assert(ret == 0);
    assert(head->bad_wr == NULL);
    return 1;
}

void flush_data_simple(pmrep_ctx_t *pctx, void *addr,
                       size_t bytes, int lazy_write)
{
    struct ibv_send_wr *wr = NULL;
    struct ibv_sge *sge = NULL;
    struct mcsqnode_t qnode = {}, qnode2 = {};
    struct buf_metainfo *minfo = &pctx->write_bufinfo;
    struct pdlist *pdlist = (struct pdlist *)pctx->send_bufinfo.buffer;
    struct swr_list_info *pos, *tmp;
    off_t offset = (uintptr_t)addr - (uintptr_t)minfo->buffer;
    uint32_t elems = pdlist->elems;
    uint64_t id = 0;
    int ret = 0;

    dprintf("========= FLUSH COUNT: %lu =========\n",
            ++pctx->stats.flush_count);

    dprintf("acquire swr_lock\n");
    spin_lock(&pctx->swr_lock, &qnode);

    /* take an entry from free slist and put in the write list */
    list_for_each_entry_safe(pos, tmp, &pctx->free_lhead_swr, node) {
        dprintf("got node with id: %lu\n", pos->wr.wr_id);
        list_move_tail(&pos->node, &minfo->wr_lhead);
        wr = &pos->wr;
        sge = &pos->sge;
        break;
    }

    pdlist->list[elems].ptr = (uintptr_t)addr;
    pdlist->list[elems].len = bytes;
    pdlist->elems++;

    spin_unlock(&pctx->swr_lock, &qnode);
    dprintf("release swr_lock\n");

    update_sge(sge, (uintptr_t)addr, bytes, minfo->mr->lkey);
    update_send_wr(wr, sge, IBV_WR_RDMA_WRITE, 0,
                   minfo->remote_data->buf_va + offset,
                   minfo->remote_data->buf_rkey);

    id = wr->wr_id;
    dprintf("check for no free wrs\n");
    if (!list_empty(&pctx->free_lhead_swr)) {
        if (!lazy_write) {
            dprintf("still free wrs, post wr with id: %lu\n", wr->wr_id);
            pctx->persist_wr_bits[id] = 1;
            ret = ibv_post_send(pctx->rcm.qp, wr, &pos->bad_wr);
            assert(ret == 0);
            assert(pos->bad_wr == NULL);
        }
    } else {
        dprintf("now, the free list is empty, need to perform "
                "this one as signaled\n");
        if (!lazy_write) {
            wr->send_flags |= IBV_SEND_SIGNALED;
            pctx->persist_wr_bits[id] = 1;
            ret = ibv_post_send(pctx->rcm.qp, wr, &pos->bad_wr);
            assert(ret == 0);
            assert(pos->bad_wr == NULL);

            poll_send_cq(pctx, id);
            spin_lock(&pctx->swr_lock, &qnode2);
            clean_wlist(pctx);
            spin_unlock(&pctx->swr_lock, &qnode2);
        } else {
            wr->send_flags |= IBV_SEND_SIGNALED;
            bulk_flush_data(pctx);
            poll_send_cq(pctx, id);

            spin_lock(&pctx->swr_lock, &qnode2);
            clean_wlist(pctx);
            spin_unlock(&pctx->swr_lock, &qnode2);
        }
    }
}

static inline struct swr_list_info *persist_data(pmrep_ctx_t *pctx,
                                                int read_flag, persistence_t pt)
{
    struct buf_metainfo *minfo = NULL;
    struct ibv_send_wr *wr = NULL;
    struct ibv_sge *sge = NULL;
    struct swr_list_info *swr_node = NULL, *pos, *tmp;
    int wr_send_flag = 0;
    size_t buf_size = 0;
    struct mcsqnode_t qnode = {};
    int ret = 0;
    struct pdlist *pdlist = NULL;
#ifdef DPRINT
    char msg[L1D_CACHELINE_BYTES];
#endif

    dprintf("flushing out the write wrs\n");
    ret = bulk_flush_data(pctx);
    if (!ret)
        goto out;

    if (read_flag) {
        dprintf("the persistence is based on RDMA READS\n");
        minfo = &pctx->read_bufinfo;
        wr_send_flag = IBV_WR_RDMA_READ;
        buf_size = sizeof(int);
    } else {
        dprintf("RDMA SENDS with persistence: %s\n", get_pt_name(pt, msg));
        minfo = &pctx->send_bufinfo;
        pdlist = (struct pdlist *)minfo->buffer;
        pdlist->pt = pt;
        wr_send_flag = IBV_WR_SEND;
        buf_size = sizeof(persistence_t) + sizeof(uint32_t) +
            sizeof(uint64_t) + pdlist->elems * sizeof(struct pdentry);
    }

    dprintf("acquire swr_lock\n");
    spin_lock(&pctx->swr_lock, &qnode);

    /* get the free swr and add to the read list */
    list_for_each_entry_safe(pos, tmp, &pctx->free_lhead_swr, node) {
        swr_node = pos;
        dprintf("got node with id: %lu\n", swr_node->wr.wr_id);
        list_move_tail(&swr_node->node, &minfo->wr_lhead);
        wr = &swr_node->wr;
        sge = &swr_node->sge;
        break;
    }

    if (!read_flag)
        pdlist->wr_id = wr->wr_id;
    update_sge(sge, (uintptr_t)minfo->buffer, buf_size, minfo->mr->lkey);
    update_send_wr(wr, sge, wr_send_flag, IBV_SEND_SIGNALED,
                   minfo->remote_data->buf_va,
                   minfo->remote_data->buf_rkey);

    spin_unlock(&pctx->swr_lock, &qnode);
    dprintf("release swr_lock\n");

    dprintf("ibv post send for id: %lu\n", wr->wr_id);
    ret = ibv_post_send(pctx->rcm.qp, wr, &swr_node->bad_wr);
    assert(ret == 0);
 out:
    return swr_node;
}

void persist_data_wread(pmrep_ctx_t *pctx)
{
    struct swr_list_info *swr_node = NULL;
    uint64_t id = 0;

    dprintf("========= PERSIST COUNT: %lu =========\n",
            ++pctx->stats.persist_count);

    dprintf("persist via reads\n");
    swr_node = persist_data(pctx, 1, NO_PERSISTENCE);
    if (!swr_node)
        return;

    id = swr_node->wr.wr_id;
    dprintf("polling for the read wr id: %lu\n", id);
    poll_send_cq(pctx, id);

    dprintf("since there is time, cleaning up the send list\n");
    clean_slist(pctx, swr_node);
}

void persist_data_wsend(pmrep_ctx_t *pctx, persistence_t pt)
{
    struct swr_list_info *swr_node = NULL;
    uint64_t recv_wr_id;

    dprintf("persist via sends\n");
    swr_node = persist_data(pctx, 0, pt);
    if (!swr_node)
        return;

    if (pctx->recv_posted_count < MAX_POST_RECVS / 2) {
        dprintf("post receives (%lu) less than half of %d",
                pctx->recv_posted_count, MAX_POST_RECVS);
        post_recv_wr(pctx, 1, pctx->recv_bufinfo.size);
    }

    /* poll for wsend */
    dprintf("polling for the send wr id: %lu\n", swr_node->wr.wr_id);
    poll_send_cq(pctx, swr_node->wr.wr_id);

    dprintf("since there is time, cleaning up the send list\n");
    clean_slist(pctx, swr_node);

    /* poll for the recv */
    dprintf("polling for receive wr: %lu\n", swr_node->wr.wr_id);
    recv_wr_id = poll_recv_cq(pctx, swr_node->wr.wr_id);

    dprintf("cleaning up the rlist\n");
    clean_rlist(pctx, recv_wr_id);
}

void persist_data_with_complex_writes(pmrep_ctx_t *pctx, persistence_t pt)
{
}

void setup_qp_attributes(struct ibv_qp_init_attr *qp_attr, pmrep_ctx_t *pctx)
{
    memset(qp_attr, 0 , sizeof(struct ibv_qp_init_attr));
    qp_attr->send_cq = pctx->rcm.send_cq;
    qp_attr->recv_cq = pctx->rcm.recv_cq;

    qp_attr->cap.max_send_wr = MAX_SEND_WR;
    qp_attr->cap.max_recv_wr = MAX_RECV_WR;
    qp_attr->cap.max_send_sge = MAX_SEND_SGES;
    qp_attr->cap.max_recv_sge = MAX_RECV_SGES;
    qp_attr->cap.max_inline_data = MAX_INLINE_DATA;

    qp_attr->qp_type = IBV_QPT_RC;
}

void setup_cm_parameters(struct rdma_conn_param *cm_param)
{
    memset(cm_param, 0, sizeof(struct rdma_conn_param));
    cm_param->responder_resources = 0xFF;
    cm_param->initiator_depth = 0xFF;
    cm_param->retry_count = DEFAULT_RETRY_COUNT;
    cm_param->rnr_retry_count = DEFAULT_RNR_RETRY_COUNT;
}

static void init_metainfo(struct buf_metainfo *minfo, struct ibv_pd *pd,
                          int alloc, uint8_t *ptr, size_t size, char *str,
                          struct remote_regdata *remote_data)
{
    if (alloc)
        minfo->buffer = mem_alloc_pgalign(size, str);
    else
        minfo->buffer = ptr;
    assert(minfo->buffer);
    minfo->size = size;
    INIT_LIST_HEAD(&minfo->wr_lhead);
    minfo->remote_data = remote_data;
    minfo->mr = ibv_reg_mr(pd, minfo->buffer, size, IBV_ENABLE_RDWR);
    assert(minfo->mr);
}

static void allocate_structures(pmrep_ctx_t *pctx, uint8_t *buffer,
                                size_t size, int alloc_write_buffer)
{
    int i;

    /* handling the wr info stuff */
    INIT_LIST_HEAD(&pctx->free_lhead_rwr);
    INIT_LIST_HEAD(&pctx->free_lhead_swr);

    spinlock_init(&pctx->swr_lock);
    spinlock_init(&pctx->rwr_lock);

    pctx->max_wrs = MAX_SEND_WR;
    /* allocate all the send and recv wrnodes */
    pctx->send_wrnodes = mem_alloc_pgalign(sizeof(struct swr_list_info) *
                                           MAX_SEND_WR, "Send wrs");
    assert(pctx->send_wrnodes);

    for (i = 0; i < MAX_SEND_WR; ++i) {
        struct swr_list_info *sinfo = &pctx->send_wrnodes[i];
        sinfo->wr.wr_id = i;
        list_add_tail(&sinfo->node, &pctx->free_lhead_swr);
    }

    pctx->recv_wrnodes = mem_alloc_pgalign(sizeof(struct rwr_list_info) *
                                           MAX_RECV_WR, "Receive wrs");
    assert(pctx->recv_wrnodes);
    for (i = 0; i < MAX_RECV_WR; ++i) {
        struct rwr_list_info *linfo = &pctx->recv_wrnodes[i];
        linfo->wr.wr_id = i + MAX_SEND_WR;
        list_add_tail(&linfo->node, &pctx->free_lhead_rwr);
    }

    /* handling the meta info */
    init_metainfo(&pctx->write_bufinfo, pctx->rcm.pd, alloc_write_buffer,
                  buffer, size, "Write", &pctx->remote_data[0]);
    init_metainfo(&pctx->read_bufinfo, pctx->rcm.pd, 1, NULL,
                  L1D_CACHELINE_BYTES, "Read", &pctx->remote_data[1]);
    init_metainfo(&pctx->send_bufinfo, pctx->rcm.pd, 1, NULL,
                  sizeof(struct pdlist), "Send", &pctx->remote_data[2]);
    init_metainfo(&pctx->recv_bufinfo, pctx->rcm.pd, 1, NULL,
                  sizeof(struct pdlist), "Recv", &pctx->remote_data[3]);
    pctx->persist_cq_bits = mem_alloc_pgalign(MAX_SEND_WR, "SEND cq bits");
    assert(pctx->persist_cq_bits);
    pctx->recv_cq_bits = mem_alloc_pgalign(MAX_SEND_WR, "RECV cq bits");
    assert(pctx->recv_cq_bits);
    pctx->persist_wr_bits = mem_alloc_pgalign(MAX_SEND_WR, "SEND wr bits");
    assert(pctx->persist_wr_bits);
    pctx->recv_wr_bits = mem_alloc_pgalign(MAX_RECV_WR, "RECV wr bits");
}

/* client side */
static int setup_memory_region_client(pmrep_ctx_t *pctx,
                                      uint8_t *buffer, size_t buffer_size)
{
    int ret = 0;
    struct rdma_conn_param cm_param;
    struct ibv_qp_init_attr qp_attr;

    /* get the context */
    pctx->rcm.ctx = pctx->rcm.id->verbs;

    /* protection domain */
    pctx->rcm.pd = ibv_alloc_pd(pctx->rcm.ctx);
    assert(pctx->rcm.pd != NULL);

    /* allocate memory for the reading */
    allocate_structures(pctx, buffer, buffer_size, !buffer?1:0);

    /* completion channel */
    pctx->rcm.comp_channel = ibv_create_comp_channel(pctx->rcm.ctx);
    assert(pctx->rcm.comp_channel != NULL);

    /* completion queue */
    pctx->rcm.send_cq = ibv_create_cq(pctx->rcm.ctx, NUM_CQES, NULL,
                                      pctx->rcm.comp_channel, 0);
    assert(pctx->rcm.send_cq != NULL);

    pctx->rcm.recv_cq = ibv_create_cq(pctx->rcm.ctx, NUM_CQES, NULL,
                                      pctx->rcm.comp_channel, 0);
    assert(pctx->rcm.recv_cq != NULL);

    setup_qp_attributes(&qp_attr, pctx);

    /* creating the queue-pairs */
    ret = rdma_create_qp(pctx->rcm.id, pctx->rcm.pd, &qp_attr);
    assert(ret == 0);

    pctx->rcm.qp = pctx->rcm.id->qp;
    post_recv_wr(pctx, MAX_POST_RECVS, pctx->recv_bufinfo.size);

    /* time to connect */
    setup_cm_parameters(&cm_param);
    ret = rdma_connect(pctx->rcm.id, &cm_param);
    assert(ret == 0);

    ret = rdma_get_cm_event(pctx->rcm.ec, &pctx->rcm.event);
    assert(ret == 0);

    assert(pctx->rcm.event->event == RDMA_CM_EVENT_ESTABLISHED);

    /* getting the data from the server about the address and the length */
    memcpy(pctx->remote_data, pctx->rcm.event->param.conn.private_data,
           sizeof(pctx->remote_data));

    rdma_ack_cm_event(pctx->rcm.event);

    return 0;
}

int setup_region_client(pmrep_ctx_t *pctx, uint8_t *buffer, size_t buffer_size)
{
    struct addrinfo *addr;
    int ret = 0;
    char rdma_port[16];

    dprintf("setting up the meta information on the client side\n");

    memset(rdma_port, 0, sizeof(rdma_port));
    ret = client_getset_info(buffer_size, PASSIVE_NODE_IP);
    sprintf(rdma_port, "%d", ret);

    /* connection setup */
    ret = getaddrinfo(PASSIVE_NODE_IP, rdma_port, NULL, &addr);
    assert(ret == 0);

    pctx->rcm.ec = rdma_create_event_channel();
    assert(pctx->rcm.ec != NULL);

    ret = rdma_create_id(pctx->rcm.ec, &pctx->rcm.id, NULL, RDMA_PS_TCP);
    assert(ret != -1);

    ret = rdma_resolve_addr(pctx->rcm.id, NULL,
                            addr->ai_addr, CONNECTION_TIMEOUT);
    assert(ret == 0);

    ret = rdma_get_cm_event(pctx->rcm.ec, &pctx->rcm.event);
    assert(ret == 0);

    assert(pctx->rcm.event->event == RDMA_CM_EVENT_ADDR_RESOLVED);
    rdma_ack_cm_event(pctx->rcm.event);

    ret = rdma_resolve_route(pctx->rcm.id, CONNECTION_TIMEOUT);
    assert(ret == 0);

    ret = rdma_get_cm_event(pctx->rcm.ec, &pctx->rcm.event);
    assert(ret == 0);

    assert(pctx->rcm.event->event == RDMA_CM_EVENT_ROUTE_RESOLVED);
    rdma_ack_cm_event(pctx->rcm.event);

    ret = setup_memory_region_client(pctx, buffer, buffer_size);
    assert (ret == 0);

    dprintf("meta information setup done\n");

    return 0;
}

/* server side */
void setup_memory_region_server(pmrep_ctx_t *pctx, size_t buffer_size)
{
    struct rdma_conn_param cm_param;
    struct ibv_qp_init_attr qp_attr;
    int ret = 0;

    pctx->rcm.ctx = pctx->rcm.id->verbs;

    pctx->rcm.pd = ibv_alloc_pd(pctx->rcm.ctx);
    assert(pctx->rcm.pd != NULL);

    allocate_structures(pctx, NULL, buffer_size, 1);

    pctx->rcm.comp_channel = ibv_create_comp_channel(pctx->rcm.ctx);
    assert(pctx->rcm.comp_channel != NULL);

    /* completion queue */
    pctx->rcm.send_cq = ibv_create_cq(pctx->rcm.ctx, NUM_CQES, NULL,
                                      pctx->rcm.comp_channel, 0);
    assert(pctx->rcm.send_cq != NULL);

    pctx->rcm.recv_cq = ibv_create_cq(pctx->rcm.ctx, NUM_CQES, NULL,
                                      pctx->rcm.comp_channel, 0);
    assert(pctx->rcm.recv_cq != NULL);

    setup_qp_attributes(&qp_attr, pctx);

    /* creating the queue-pairs */
    ret = rdma_create_qp(pctx->rcm.id, pctx->rcm.pd, &qp_attr);
    assert(ret == 0);

    pctx->rcm.qp = pctx->rcm.id->qp;
    post_recv_wr(pctx, MAX_POST_RECVS, pctx->recv_bufinfo.size);

    pctx->remote_data[0].buf_va = (uintptr_t)pctx->write_bufinfo.buffer;
    pctx->remote_data[0].buf_rkey = pctx->write_bufinfo.mr->rkey;
    pctx->remote_data[1].buf_va = (uintptr_t)pctx->read_bufinfo.buffer;
    pctx->remote_data[1].buf_rkey = pctx->read_bufinfo.mr->rkey;
    pctx->remote_data[2].buf_va = (uintptr_t)pctx->send_bufinfo.buffer;
    pctx->remote_data[2].buf_rkey = pctx->send_bufinfo.mr->rkey;
    pctx->remote_data[3].buf_va = (uintptr_t)pctx->recv_bufinfo.buffer;
    pctx->remote_data[3].buf_rkey = pctx->recv_bufinfo.mr->rkey;

    setup_cm_parameters(&cm_param);
    cm_param.responder_resources = 1;
    cm_param.private_data = pctx->remote_data;
    cm_param.private_data_len = sizeof(pctx->remote_data);

    ret = rdma_accept(pctx->rcm.id, &cm_param);
    assert(ret == 0);

    ret = rdma_get_cm_event(pctx->rcm.ec, &pctx->rcm.event);
    assert(ret == 0);

    assert(pctx->rcm.event->event == RDMA_CM_EVENT_ESTABLISHED);

    rdma_ack_cm_event(pctx->rcm.event);

    ibv_ack_cq_events(pctx->rcm.recv_cq, 1);
}

int setup_region_server(pmrep_ctx_t *pctx)
{
    struct sockaddr_in6 addr;
    size_t buffer_size;
    int ret = 0;
    int port;

    dprintf("setting up the meta information on the server side\n");

    pctx->rcm.ec = rdma_create_event_channel();
    assert(pctx->rcm.ec != NULL);

    ret = rdma_create_id(pctx->rcm.ec, &pctx->rcm.sid, NULL, RDMA_PS_TCP);
    assert(ret != -1);

    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;

    ret = rdma_bind_addr(pctx->rcm.sid, (struct sockaddr *)&addr);
    assert(ret != -1);

    ret = rdma_listen(pctx->rcm.sid, SERVER_LISTEN_BACKLOG);
    assert(ret != -1);

    port = ntohs(rdma_get_src_port(pctx->rcm.sid));
    buffer_size = server_setget_info(port);

    ret = rdma_get_cm_event(pctx->rcm.ec, &pctx->rcm.event);
    assert(ret == 0);

    pctx->rcm.id = pctx->rcm.event->id;
    rdma_ack_cm_event(pctx->rcm.event);

    assert(pctx->rcm.event->event == RDMA_CM_EVENT_CONNECT_REQUEST);

    setup_memory_region_server(pctx, buffer_size);

    return 0;
}


static void dealloc_metainfo(struct buf_metainfo *minfo, int dealloc)
{
    ibv_dereg_mr(minfo->mr);
    if (dealloc)
        free(minfo->buffer);
    minfo->buffer = NULL;
}

void clear_region(pmrep_ctx_t *pctx, int free_buffer)
{
    dealloc_metainfo(&pctx->write_bufinfo, free_buffer);
    dealloc_metainfo(&pctx->read_bufinfo, 1);
    dealloc_metainfo(&pctx->send_bufinfo, 1);
    dealloc_metainfo(&pctx->recv_bufinfo, 1);

    ibv_destroy_cq(pctx->rcm.send_cq);
    ibv_destroy_cq(pctx->rcm.recv_cq);
    ibv_destroy_comp_channel(pctx->rcm.comp_channel);
    ibv_dealloc_pd(pctx->rcm.pd);
    rdma_destroy_id(pctx->rcm.id);
    if (pctx->rcm.sid)
        rdma_destroy_id(pctx->rcm.sid);
    rdma_destroy_event_channel(pctx->rcm.ec);

    free(pctx->send_wrnodes);
    free(pctx->recv_wrnodes);
    free(pctx->persist_cq_bits);
    free(pctx->recv_cq_bits);
    free(pctx->persist_wr_bits);
    free(pctx->recv_wr_bits);

    pctx->rcm.send_cq = NULL;
    pctx->rcm.recv_cq = NULL;
    pctx->rcm.comp_channel = NULL;
    pctx->rcm.pd = NULL;
    pctx->rcm.id = NULL;
    pctx->rcm.ec = NULL;
    pctx->send_wrnodes = NULL;
    pctx->recv_wrnodes = NULL;
    pctx->persist_cq_bits = NULL;
    pctx->recv_cq_bits = NULL;
    pctx->persist_wr_bits = NULL;
    pctx->recv_wr_bits = NULL;
}
