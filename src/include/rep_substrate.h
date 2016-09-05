#ifndef REP_SUBSTRATE_H_
#define REP_SUBSTRATE_H_

#include <pthread.h>
#include <sys/types.h>

#include "arch.h"
#include "list.h"
#include "util.h"

#include <infiniband/arch.h>
#include <rdma/rdma_cma.h>

/*
 * Number of backlogs allowed for the incoming
 * connection, currently it is 16
 */
#define SERVER_LISTEN_BACKLOG   (1 << 4)

#define NUM_CQES    (1 << 20)

/*
 * Maximum number of outstanding WSs oin the SQ/RQ
 * XXX: generate conf and read it from there
 */
#define MAX_SEND_WR         8192
#define MAX_RECV_WR         1024
#define MAX_POST_RECVS      512

/*
 * Maximum number of scatter / gatter elements in the SQ / RQ
 */
#define MAX_SEND_SGES   4
#define MAX_RECV_SGES   MAX_SEND_SGES

/*
 * max number of compound writes for sends
 */
#define MAX_COMPOUND_ENTRIES  (1 << 10)

/*
 * Enable everything
 */
#define IBV_ENABLE_WRITES (IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE)
#define IBV_ENABLE_RDWR (IBV_ACCESS_REMOTE_READ | IBV_ENABLE_WRITES)

/*
 * Timeout on the client side (milliseconds)
 */
#define CONNECTION_TIMEOUT (500)

/*
 * Connection parameter setting
 */
#define DEFAULT_RETRY_COUNT     (7)
#define DEFAULT_RNR_RETRY_COUNT (7)

/*
 * Inline data size
 */
#define MAX_INLINE_DATA  128

#define RDMA_PORT       "20480"
#define PASSIVE_NODE_IP "192.168.0.1" /* bumblebee */

typedef enum {
    NO_PERSISTENCE,
    WEAK_PERSISTENCE,
    STRONG_PERSISTENCE,
}persistence_t;

struct remote_regdata {
    uint64_t buf_va;
    uint32_t buf_rkey;
};

struct pdentry {
    uint64_t ptr;
    size_t len;
};

struct pdlist {
    persistence_t pt;
    uint32_t elems;
    uint64_t wr_id;
    struct pdentry list[MAX_COMPOUND_ENTRIES];
};

struct error_name {
    int value;
    char *name;
};

struct swr_list_info {
    struct ibv_send_wr  wr, *bad_wr;
    struct ibv_sge      sge;
    struct list_head    node;
};

struct rwr_list_info {
    struct ibv_recv_wr  wr, *bad_wr;
    struct ibv_sge      sge;
    struct list_head    node;
};

struct rdma_cm {
    /* rdma stuff */
    struct rdma_event_channel   *ec;
    struct rdma_cm_event        *event;
    struct rdma_cm_id           *id;

    /* ib stuff */
    struct ibv_pd               *pd;
    struct ibv_cq               *send_cq;
    struct ibv_cq               *recv_cq;
    struct ibv_comp_channel     *comp_channel;
    struct ibv_context          *ctx;
    struct ibv_qp               *qp;
};

struct buf_metainfo {
    /* main buffer pointer */
    uint8_t *buffer;
    /* size of the buffer */
    size_t size;
    /* associated mr */
    struct ibv_mr *mr;
    /* stats */
    uint64_t    count;
    /* pointer to the buf metainfo */
    struct remote_regdata *remote_data;
    /* associated wr ids in the form of linked list (optional) */
    struct list_head wr_lhead;
} ____cacheline_aligned;

struct pm_stats {
    /* cleanup stats */
    uint64_t clean_slist_count;
    uint64_t clean_wlist_count;
    uint64_t clean_rlist_count;

    /* poll stats */
    uint64_t poll_send_count;
    uint64_t poll_recv_count;

    /* bulk call */
    uint64_t bulk_flush_count;

    /* flush_call */
    uint64_t flush_count;

    /* persist call */
    uint64_t persist_count;

    /* post recv count */
    uint64_t post_recv_count;
} ____cacheline_aligned;

typedef struct pmrep_ctx {
    /* high level connection management */
    struct rdma_cm          rcm;

    /* write buffer metainfo */
    struct buf_metainfo     write_bufinfo ____cacheline_aligned;
    /* send buffer metainfo */
    struct buf_metainfo     send_bufinfo ____cacheline_aligned;
    /* recv buffer metainfo */
    struct buf_metainfo     recv_bufinfo ____cacheline_aligned;
    /* read buffer metainfo */
    struct buf_metainfo     read_bufinfo ____cacheline_aligned;

    /* remote mr and buffer pointer info */
    struct remote_regdata  remote_data[4];

    /* 1 to n mapping of work requests and sges */
    struct swr_list_info    *send_wrnodes ____cacheline_aligned;
    struct rwr_list_info    *recv_wrnodes ____cacheline_aligned;

    /* max allowed wrs */
    uint64_t                max_wrs;
    uint64_t                recv_posted_count;

    /* swr free list */
    struct list_head        free_lhead_swr;
    /* rwr free list */
    struct list_head        free_lhead_rwr ____cacheline_aligned;

    /* two finegrained lock for sending and receiving */
    struct mcslock_t        swr_lock ____cacheline_aligned;
    struct mcslock_t        rwr_lock ____cacheline_aligned;

    /* publication list for the wce for send and receives */
    uint8_t                 *persist_cq_bits ____cacheline_aligned;
    uint8_t                 *recv_cq_bits ____cacheline_aligned;
    /*
     * used or set bits for wrs for send and receive
     * 0 -> data is not yet posted
     * 1 -> data has been posted but not removed
     */
    uint8_t                 *persist_wr_bits ____cacheline_aligned;
    uint8_t                 *recv_wr_bits ____cacheline_aligned;

#ifdef DPRINT
    struct pm_stats         stats;
#endif
} pmrep_ctx_t ____cacheline_aligned;

int setup_region_client(pmrep_ctx_t *pctx, uint8_t *buffer, size_t buffer_size);
void clear_region(pmrep_ctx_t *pctx, int free_buffer);

void flush_data_simple(pmrep_ctx_t *pctx, void *addr,
                       size_t bytes, int lazy_write);
void persist_data_wread(pmrep_ctx_t *pctx);
void persist_data_wsend(pmrep_ctx_t *pctx, persistence_t pt);
void persist_data_with_complex_writes(pmrep_ctx_t *pctx, persistence_t pt);

#endif /* __REP_SUBSTRATE_H_ */
