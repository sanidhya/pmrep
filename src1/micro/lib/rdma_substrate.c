#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "rdma_substrate.h"
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

struct error_name persistence_type[] = {
    { NO_PERSISTENCE_DDIO,             "No persistence + DDIO " },
    { NO_PERSISTENCE_NODDIO,           "No persistence - DDIO" },
    { WEAK_PERSISTENCE_WITH_ADR_DDIO,  "Weak persistence + ADR + DDIO" },
    { WEAK_PERSISTENCE_WITH_ADR_NODDIO,"Weak persistence + ADR - DDIO" },
    { WEAK_PERSISTENCE_WITH_eADR_DDIO, "Weak persistence + eADR + DDIO" },
    { WEAK_PERSISTENCE_WITH_eADR_NODDIO, "Weak persistence + eADR - DDIO" },
    { STRONG_PERSISTENCE_WITH_ADR_DDIO, "Strong persistence + ADR + DDIO" },
    { STRONG_PERSISTENCE_WITH_ADR_NODDIO, "Strong persistence + ADR - DDIO" },
    { STRONG_PERSISTENCE_WITH_eADR_DDIO, "Strong persistence + eADR + DDIO" },
    { STRONG_PERSISTENCE_WITH_eADR_NODDIO, "Strong persistence + eADR - DDIO" },
};

inline char *get_value(int value, struct error_name *name_array,
                              char *data, size_t size)
{
    strncpy(data, name_array[value].name, size);
    data[size - 1] = '\0';
    return data;
}

inline char *get_pt_name(persistence_t pt, char *data)
{
    return get_value(pt, persistence_type, data, L1D_CACHELINE_BYTES);
}

inline char *get_wr_status_name(int status, char *data, size_t size)
{
    return get_value(status, cq_errors, data, size);
}

inline char *get_cm_event_name(int event, char *data, size_t size)
{
    return get_value(event, cm_events, data, size);
}

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

static inline void poll_recv_cq(struct ibv_cq *cq, struct ibv_wc *wc)
{
    char correct_msg[L1D_CACHELINE_BYTES], wrong_msg[L1D_CACHELINE_BYTES];
    int n = 0;

    do {
        n = ibv_poll_cq(cq, 1, wc);
    } while (n == 0);

    if (wc->status != IBV_WC_SUCCESS) {
        fprintf(stderr, "Persist: expected: %s, got: %s\n",
                get_wr_status_name(IBV_WC_SUCCESS,
                                   correct_msg, L1D_CACHELINE_BYTES),
                get_wr_status_name(wc->status,
                                   wrong_msg, L1D_CACHELINE_BYTES));
        assert(0);

    }
}

static inline struct rwr_list_info *poll_recv_cq_server(rep_ctx_t *pctx,
                                                        int thread_id)
{
    struct ibv_wc wc = {};

    poll_recv_cq(pctx->rcm.recv_cq, &wc);
    dprintf("thread: %d id: %lu\n", thread_id, wc.wr_id);
    assert(wc.wr_id >= pctx->total_flush_wrs + pctx->total_persist_wrs);
    return get_rnode(pctx->recv_bufinfo.recv_wrnodes, wc.wr_id,
                     pctx->total_recv_wrs);
}

static inline struct rwr_list_info *poll_recv_cq_client(rep_ctx_t *pctx,
                                                        uint64_t id,
                                                        int thread_id)
{
    struct rwr_list_info *rwr_node;
    struct ibv_wc wc = {};

    poll_recv_cq(pctx->rcm.recv_cq, &wc);
    assert(wc.wr_id >= pctx->total_flush_wrs + pctx->total_persist_wrs);
    rwr_node = get_rnode(pctx->recv_bufinfo.recv_wrnodes,
                         wc.wr_id, pctx->total_recv_wrs);
    pctx->recv_cq_bits[wc.imm_data] = 1;
    smp_wmb();

    while (pctx->recv_cq_bits[id] == 0) {
        smp_rmb();
    }
    return rwr_node;
}

static inline void poll_send_cq(rep_ctx_t *pctx, uint64_t id, int thread_id)
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

/* sge and wr update */
static void inline update_sge(struct ibv_sge *sge, uint64_t addr,
                              uint32_t length, uint32_t lkey)
{
#ifdef DPRINT
    assert(sge);
#endif
    dprintf("SGE update addr: %lx len: %u\n", addr, length);
    sge->addr = addr;
    sge->length = length;
    sge->lkey = lkey;
}

static inline void update_send_wr(struct ibv_send_wr *wr, struct ibv_sge *sge,
                                  int opcode, int send_flags,
                                  uint64_t raddr, uint32_t rkey)
{
    dprintf("SEND WR update wr id: %lu\n", wr->wr_id);
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

static inline void update_recv_wr(struct ibv_recv_wr *wr,
                                  struct ibv_sge *sge)
{
    dprintf("RECV WR update wr id: %lu\n", wr->wr_id);
    wr->sg_list = sge;
    wr->num_sge = sge?1:0;
    wr->next = NULL;
}

static inline void get_and_post_recv_wr(rep_ctx_t *pctx,
                                        struct rwr_list_info *rwr_node,
                                        uint64_t sid)
{
    int ret;

    pctx->recv_cq_bits[sid] = 0;
    ret = ibv_post_recv(pctx->rcm.qp, &rwr_node->wr, &rwr_node->bad_wr);
    assert(ret == 0);
    assert(rwr_node->bad_wr == NULL);
}

static void post_recv_wr(struct ibv_qp *qp, struct rwr_list_info *rwr_node)
{
    int ret = 0;
    dprintf("ibv_post_recv wr id: %lu\n", rwr_node->wr.wr_id);
    memset(rwr_node->buffer, 0, rwr_node->size);
    ret = ibv_post_recv(qp, &rwr_node->wr, &rwr_node->bad_wr);
    assert(ret == 0);
    assert(rwr_node->bad_wr == NULL);
}

static inline void clean_write_list(rep_ctx_t *pctx, int thread_id)
{
    struct thread_block *tblock = &pctx->thread_blocks[thread_id];
    struct buf_metainfo *minfo = &tblock->flush_bufinfo;
    struct swr_list_info *pos, *tmp;

    if (list_empty(&minfo->busy_lhead))
        return;

    list_for_each_entry_safe(pos, tmp, &minfo->busy_lhead, node) {
        list_move(&pos->node, &minfo->free_lhead);
    }
}

inline void flush_data_simple(rep_ctx_t *pctx, void *addr,
                       size_t bytes, int lazy_write, int thread_id)
{
    struct thread_block *tblock = &pctx->thread_blocks[thread_id];
    struct buf_metainfo *minfo = &tblock->flush_bufinfo;
    struct swr_list_info *pos, *tmp;
    struct ibv_send_wr *wr = NULL;
    struct ibv_sge *sge = NULL;
    off_t offset = (uintptr_t)addr - (uintptr_t)minfo->buffer;
    int ret = 0;
    uint64_t remote_addr = minfo->remote_data->buf_va + offset;
    int write_signaled = 0;


    list_for_each_entry_safe(pos, tmp, &minfo->free_lhead, node) {
        list_move_tail(&pos->node, &minfo->busy_lhead);
        break;
    }

    if (list_empty(&minfo->free_lhead))
        write_signaled = 1;

    wr = &pos->wr;
    sge = &pos->sge;
    assert(wr->wr_id < pctx->total_flush_wrs + pctx->total_persist_wrs);

    update_sge(sge, (uintptr_t)addr, bytes, minfo->mr->lkey);
    update_send_wr(wr, sge, IBV_WR_RDMA_WRITE,
                   write_signaled?IBV_SEND_SIGNALED:IBV_SEND_NOSIGNAL,
                   remote_addr, minfo->remote_data->buf_rkey);
    ret = ibv_post_send(pctx->rcm.qp, wr, &pos->bad_wr);
    assert(ret == 0);
    assert(pos->bad_wr == NULL);

    if (write_signaled) {
        poll_send_cq(pctx, wr->wr_id, thread_id);
        clean_write_list(pctx, thread_id);
    }
}

void setup_qp_attributes(struct ibv_qp_init_attr *qp_attr, rep_ctx_t *pctx)
{
    memset(qp_attr, 0 , sizeof(struct ibv_qp_init_attr));
    qp_attr->qp_type = IBV_QPT_RC;
    qp_attr->send_cq = pctx->rcm.send_cq;
    qp_attr->recv_cq = pctx->rcm.recv_cq;

    qp_attr->cap.max_send_wr = MAX_WRS;
    qp_attr->cap.max_recv_wr = MAX_WRS;
    qp_attr->cap.max_send_sge = MAX_SEND_SGES;
    qp_attr->cap.max_recv_sge = MAX_RECV_SGES;
    qp_attr->cap.max_inline_data = MAX_INLINE_DATA;
}

void setup_cm_parameters(struct rdma_conn_param *cm_param)
{
    memset(cm_param, 0, sizeof(struct rdma_conn_param));
    cm_param->responder_resources = 0xFF;
    cm_param->initiator_depth = 0xFF;
    cm_param->retry_count = DEFAULT_RETRY_COUNT;
    cm_param->rnr_retry_count = DEFAULT_RNR_RETRY_COUNT;
}

static void init_metainfo_send(rep_ctx_t *pctx, struct buf_metainfo *minfo,
                               int alloc, uint8_t *ptr, size_t size, char *str,
                               struct remote_regdata *remote_data,
                               int thread_id, uint64_t wr_gap, uint64_t pt_wrs)
{
    uint64_t i;

    if (alloc)
        minfo->buffer = mem_alloc_pgalign(size, str);
    else
        minfo->buffer = ptr;
    assert(minfo->buffer);
    minfo->size = size;
    INIT_LIST_HEAD(&minfo->busy_lhead);
    INIT_LIST_HEAD(&minfo->free_lhead);
    for (i = 0; i < pt_wrs; ++i)
        list_add_tail(&pctx->persist_wrnodes[i + thread_id * pt_wrs +
                      wr_gap].node, &minfo->free_lhead);
    minfo->remote_data = remote_data;
    minfo->mr = ibv_reg_mr(pctx->rcm.pd, minfo->buffer, size, IBV_ENABLE_RDWR);
    assert(minfo->mr);
}

static void update_wr_info(rep_ctx_t *pctx)
{
    int num_threads = pctx->num_threads;
    int max_wr = MAX_RECV_WRS;

    if (max_wr < num_threads)
        max_wr = num_threads;
    pctx->pt_recv_wrs = max_wr / num_threads;
    pctx->pt_persist_wrs = pctx->pt_recv_wrs;
    pctx->total_recv_wrs = num_threads * pctx->pt_recv_wrs;
    pctx->total_persist_wrs = num_threads * pctx->pt_persist_wrs;
    pctx->pt_flush_wrs = (MAX_WRS - (pctx->pt_recv_wrs * 2) - 1) / num_threads;
    pctx->total_flush_wrs = pctx->pt_flush_wrs * num_threads;
}


static void allocate_structures(rep_ctx_t *pctx, uint8_t *buffer, size_t size,
                                int alloc_write_buffer)
{
    uint64_t i;
    int t;
    struct thread_block *tblocks;
    int num_threads = pctx->num_threads;
    update_wr_info(pctx);
    int total_send_wrs = pctx->total_flush_wrs + pctx->total_persist_wrs;
    int total_recv_wrs = pctx->total_recv_wrs;
    size_t rd_size = num_threads * OPS_TYPE * sizeof(struct remote_regdata);
    size_t max_rdsize = ONLINE_CORES * OPS_TYPE * sizeof(struct remote_regdata);
    struct rwr_list_info *recv_wrnodes;
    size_t pdlist_size = sizeof(struct pdlist);
    size_t rbuf_size;
    uint64_t rbuf_ptr;

    pctx->ctrl_bufinfo.buffer = mem_alloc_pgalign(max_rdsize, "Ctrl op");
    pctx->ctrl_bufinfo.mr = ibv_reg_mr(pctx->rcm.pd, pctx->ctrl_bufinfo.buffer,
                                       max_rdsize, IBV_ENABLE_RDWR);
    assert(pctx->ctrl_bufinfo.mr);
    pctx->ctrl_bufinfo.wr.wr_id = total_send_wrs;

    pctx->thread_blocks = mem_alloc_pgalign(num_threads * sizeof(*tblocks),
                                            "Thread alloc");
    tblocks = pctx->thread_blocks;
    /* allocate all the send and recv wrnodes */
    pctx->persist_wrnodes = mem_alloc_pgalign(sizeof(struct swr_list_info) *
                                           total_send_wrs, "Send wrs");
    assert(pctx->persist_wrnodes);
    for (i = 0; i < total_send_wrs; ++i)
        pctx->persist_wrnodes[i].wr.wr_id = i;

    rbuf_size = sizeof(struct rwr_list_info) * total_recv_wrs;
    pctx->recv_bufinfo.recv_wrnodes =
        mem_alloc_pgalign(rbuf_size, "Receive wrs");
    assert(pctx->recv_bufinfo.recv_wrnodes);

    pctx->recv_bufinfo.size = pctx->total_recv_wrs * sizeof(struct pdlist);
    pctx->recv_bufinfo.buffer = mem_alloc_pgalign(pctx->recv_bufinfo.size,
                                                  "Recv buffer");
    pctx->recv_bufinfo.mr = ibv_reg_mr(pctx->rcm.pd, pctx->recv_bufinfo.buffer,
                                       pctx->recv_bufinfo.size,
                                       IBV_ENABLE_RDWR);
    assert(pctx->recv_bufinfo.mr);

    recv_wrnodes = pctx->recv_bufinfo.recv_wrnodes;
    rbuf_ptr = (uintptr_t)pctx->recv_bufinfo.buffer;

    for (i = 0; i < total_recv_wrs; ++i) {
        recv_wrnodes[i].wr.wr_id = i + total_send_wrs + 1;
        recv_wrnodes[i].buffer = (uint8_t *)(uintptr_t)rbuf_ptr;
        recv_wrnodes[i].size = pdlist_size;
        rbuf_ptr += pdlist_size;
    }

    pctx->remote_data = mem_alloc_pgalign(rd_size, "Remote meta info");

    /* Now, this is going to be huge!! */
    for (t = 0; t < num_threads; ++t) {
        /* handling the meta info */
        tblocks[t].pctx = pctx;
        if (t == 0) {
            init_metainfo_send(pctx, &tblocks[t].flush_bufinfo,
                               alloc_write_buffer, buffer, size, "Write",
                               &pctx->remote_data[t * OPS_TYPE], t, 0,
                               pctx->pt_flush_wrs);
            pctx->common_buffer = tblocks[t].flush_bufinfo.buffer;
        }
        else
            init_metainfo_send(pctx, &tblocks[t].flush_bufinfo,
                               0, pctx->common_buffer, size, "Write",
                               &pctx->remote_data[t * OPS_TYPE], t, 0,
                               pctx->pt_flush_wrs);

    }

    pctx->persist_cq_bits = mem_alloc_pgalign(MAX_WRS, "Persist cq bits");
    assert(pctx->persist_cq_bits);
    pctx->recv_cq_bits = mem_alloc_pgalign(MAX_WRS, "RECV cq bits");
    assert(pctx->recv_cq_bits);
}

static inline void pre_post_all_recv_wrs(rep_ctx_t *pctx)
{
    int i;
    struct ibv_mr *mr = pctx->recv_bufinfo.mr;
    struct rwr_list_info *recv_wrnodes = pctx->recv_bufinfo.recv_wrnodes;

    for (i = 0; i < pctx->total_recv_wrs; ++i) {
        struct rwr_list_info *rnode = &recv_wrnodes[i];
        struct ibv_sge *sge = &rnode->sge;
        struct ibv_recv_wr *wr = &rnode->wr;
        update_sge(sge, (uintptr_t)rnode->buffer, rnode->size, mr->lkey);
        update_recv_wr(wr, sge);
        post_recv_wr(pctx->rcm.qp, rnode);
    }
}

/* client side */

static inline void receive_mr_data(rep_ctx_t *pctx)
{
    struct ibv_wc wc = {};
    struct ibv_recv_wr *wr = NULL;
    struct ibv_sge *sge;
    size_t size = OPS_TYPE * pctx->num_threads * sizeof(struct remote_regdata);
    struct rwr_list_info *recv_wrnodes = pctx->recv_bufinfo.recv_wrnodes;
    struct rwr_list_info *rnode = NULL;
    uint64_t i;
    int ret = 0;

    do {
        ret = ibv_poll_cq(pctx->rcm.recv_cq, 1, &wc);
    } while (ret == 0);
    assert(wc.status == IBV_WC_SUCCESS);

    /* got the buffer */
    for(i = 0; i < pctx->total_recv_wrs; ++i) {
        if (recv_wrnodes[i].wr.wr_id == wc.wr_id) {
            rnode = &recv_wrnodes[i];
            break;
        }
    }
    wr = &rnode->wr;
    sge = wr->sg_list;
    memcpy(pctx->remote_data, (void *)(uintptr_t)sge->addr, size);
    dprintf("Got data\n");
    for (i = 0; i < pctx->num_threads * OPS_TYPE; ++i) {
        dprintf("%lu: buf: %lx remote-key: %u\n", i, pctx->remote_data[i].buf_va,
               pctx->remote_data[i].buf_rkey);
    }
    post_recv_wr(pctx->rcm.qp, rnode);
}

static int setup_memory_region_client(rep_ctx_t *pctx, uint8_t *buffer,
                                      size_t buffer_size)
{
    struct rdma_conn_param cm_param;
    struct ibv_qp_init_attr qp_attr;
    int ret = 0;

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

    pre_post_all_recv_wrs(pctx);

    /* time to connect */
    setup_cm_parameters(&cm_param);
    ret = rdma_connect(pctx->rcm.id, &cm_param);
    assert(ret == 0);

    ret = rdma_get_cm_event(pctx->rcm.ec, &pctx->rcm.event);
    assert(ret == 0);

    assert(pctx->rcm.event->event == RDMA_CM_EVENT_ESTABLISHED);

    /* getting the data from the server about the address and the length */
    memcpy(pctx->remote_data, pctx->rcm.event->param.conn.private_data,
           sizeof(struct remote_regdata) * pctx->num_threads * OPS_TYPE);

    rdma_ack_cm_event(pctx->rcm.event);

    receive_mr_data(pctx);

    return 0;
}

int setup_region_client(rep_ctx_t *pctx, uint8_t *buffer, size_t buffer_size,
                        int num_threads, int persist_with_reads)
{
    struct addrinfo *addr;
    int ret = 0;
    char rdma_port[16];

    dprintf("setting up the meta information on the client side\n");

    memset(rdma_port, 0, sizeof(rdma_port));
    ret = client_getset_info(buffer_size, PASSIVE_NODE_IP,
                             num_threads, persist_with_reads);
    sprintf(rdma_port, "%d", ret);

    pctx->persist_with_reads = persist_with_reads;
    assert(num_threads <= ONLINE_CORES);
    pctx->num_threads = num_threads;
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

static inline void send_mr_data(rep_ctx_t *pctx)
{
    struct ctrl_bufinfo *cminfo = &pctx->ctrl_bufinfo;
    struct ibv_send_wr *wr = &cminfo->wr;
    struct ibv_sge *sge = &cminfo->sge;
    struct ibv_wc wc = {};
    size_t size = OPS_TYPE * pctx->num_threads * sizeof(struct remote_regdata);
    uint64_t i;
    int ret;

    dprintf("Sending data\n");
    for (i = 0; i < pctx->num_threads * OPS_TYPE; ++i) {
        dprintf("%lu: buf: %lx remote-key: %u\n", i, pctx->remote_data[i].buf_va,
               pctx->remote_data[i].buf_rkey);
    }

    memcpy(cminfo->buffer, pctx->remote_data, size);
    update_sge(sge, (uintptr_t)cminfo->buffer, size, cminfo->mr->lkey);
    update_send_wr(wr, sge, IBV_WR_SEND, IBV_SEND_SIGNALED, 0, 0);

    ret = ibv_post_send(pctx->rcm.qp, wr, &cminfo->bad_wr);
    assert(ret == 0);
    assert(cminfo->bad_wr == NULL);

    do {
        ret = ibv_poll_cq(pctx->rcm.send_cq, 1, &wc);
    } while (ret == 0);

    assert(wc.status == IBV_WC_SUCCESS);
}

/* server side */
void setup_memory_region_server(rep_ctx_t *pctx, size_t buffer_size)
{
    struct rdma_conn_param cm_param;
    struct ibv_qp_init_attr qp_attr;
    int ret = 0;
    int i;

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

    /* post the recv wr */
    pre_post_all_recv_wrs(pctx);

    for (i = 0; i < pctx->num_threads; ++i) {
        pctx->remote_data[OPS_TYPE * i].buf_va =
            (uintptr_t)pctx->thread_blocks[i].flush_bufinfo.buffer;
        pctx->remote_data[OPS_TYPE * i].buf_rkey =
            pctx->thread_blocks[i].flush_bufinfo.mr->rkey;

    }

    setup_cm_parameters(&cm_param);
    cm_param.responder_resources = 1;
    cm_param.private_data = pctx->remote_data;
    cm_param.private_data_len = sizeof(struct remote_regdata) *
                                pctx->num_threads * OPS_TYPE;

    ret = rdma_accept(pctx->rcm.id, &cm_param);
    assert(ret == 0);

    ret = rdma_get_cm_event(pctx->rcm.ec, &pctx->rcm.event);
    assert(ret == 0);

    assert(pctx->rcm.event->event == RDMA_CM_EVENT_ESTABLISHED);

    rdma_ack_cm_event(pctx->rcm.event);

    ibv_ack_cq_events(pctx->rcm.recv_cq, 1);

    send_mr_data(pctx);
}

int setup_region_server(rep_ctx_t *pctx)
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
    buffer_size = server_setget_info(port, &pctx->num_threads,
                                     &pctx->persist_with_reads);

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
    if (dealloc) {
        free(minfo->buffer);
        minfo->buffer = NULL;
    }
}

void clear_region(rep_ctx_t *pctx, int free_buffer)
{
    int num_threads = pctx->num_threads, i;

    for (i = 0; i < num_threads; ++i) {
        if (i == 0)
            dealloc_metainfo(&pctx->thread_blocks[i].flush_bufinfo,
                             free_buffer);
    }

    ibv_dereg_mr(pctx->ctrl_bufinfo.mr);
    ibv_dereg_mr(pctx->recv_bufinfo.mr);
    ibv_destroy_cq(pctx->rcm.send_cq);
    ibv_destroy_cq(pctx->rcm.recv_cq);
    ibv_destroy_comp_channel(pctx->rcm.comp_channel);
    ibv_dealloc_pd(pctx->rcm.pd);
    rdma_destroy_id(pctx->rcm.id);
    if (pctx->rcm.sid)
        rdma_destroy_id(pctx->rcm.sid);
    rdma_destroy_event_channel(pctx->rcm.ec);

    free(pctx->ctrl_bufinfo.buffer);
    free(pctx->persist_wrnodes);
    free(pctx->persist_cq_bits);
    free(pctx->recv_cq_bits);
    free(pctx->recv_bufinfo.buffer);
    free(pctx->recv_bufinfo.recv_wrnodes);

    pctx->rcm.send_cq = NULL;
    pctx->rcm.recv_cq = NULL;
    pctx->rcm.comp_channel = NULL;
    pctx->rcm.pd = NULL;
    pctx->rcm.id = NULL;
    pctx->rcm.ec = NULL;
    pctx->persist_wrnodes = NULL;
    pctx->persist_cq_bits = NULL;
    pctx->recv_cq_bits = NULL;
}
