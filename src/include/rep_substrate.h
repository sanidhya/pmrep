#ifndef REP_SUBSTRATE_H_
#define REP_SUBSTRATE_H_

#include <pthread.h>
#include <sys/types.h>
#include <infiniband/arch.h>
#include <rdma/rdma_cma.h>

#include "arch.h"
#include "list.h"
#include "util.h"
#include "config.h"

#include "config.h"

/*
 * Number of backlogs allowed for the incoming
 * connection, currently it is 16
 */
#define SERVER_LISTEN_BACKLOG   (1 << 4)

#define NUM_CQES    (1 << 20)

#define OPS_TYPE 3

/*
 * Maximum number of scatter / gatter elements in the SQ / RQ
 */
#define MAX_SEND_SGES   1
#define MAX_RECV_SGES   MAX_SEND_SGES
#define MAX_RECV_WRS    255
#define MAX_PERSIST_WRS 255

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

#define IBV_SEND_NOSIGNAL   0
#define NOVALUE             0

/*
 * Inline data size
 */
#define MAX_INLINE_DATA  128

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

struct swr_list_info {
    struct ibv_send_wr  wr, *bad_wr;
    struct ibv_sge      sge;
    struct list_head    node;
};

struct rwr_list_info {
    struct ibv_recv_wr  wr, *bad_wr;
    struct ibv_sge      sge;
    struct list_head    node;
    uint8_t             *buffer;
    size_t              size;
};

struct recv_bufinfo {
    uint8_t                 *buffer;
    size_t                  size;
    struct ibv_mr           *mr;
    struct rwr_list_info    *recv_wrnodes;
};

struct rdma_cm {
    /* rdma stuff */
    struct rdma_event_channel   *ec;
    struct rdma_cm_event        *event;
    struct rdma_cm_id           *id;
    struct rdma_cm_id           *sid;

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
    struct list_head busy_lhead;
    /* associated write requests */
    struct list_head free_lhead;
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

struct pmrep_ctx;

struct thread_block {
    /* write buffer metainfo */
    struct buf_metainfo     flush_bufinfo ____cacheline_aligned;
    /* send buffer metainfo */
    struct buf_metainfo     persist_bufinfo ____cacheline_aligned;
    /* read buffer metainfo */
    struct buf_metainfo     read_bufinfo ____cacheline_aligned;

    uint64_t                recv_posted_count;
    struct pmrep_ctx        *pctx;
};

struct ctrl_bufinfo {
    struct ibv_send_wr  wr, *bad_wr;
    struct ibv_sge      sge;
    struct ibv_mr       *mr;
    uint8_t             *buffer;
    size_t              size;
};

typedef struct pmrep_ctx {
    /* number of registered threads */
    int32_t num_threads;

    /* high level connection management */
    struct rdma_cm          rcm;

    /* thread block */
    struct thread_block     *thread_blocks;

    /* remote mr and buffer pointer info */
    struct ctrl_bufinfo     ctrl_bufinfo;
    struct remote_regdata   *remote_data;

    /* 1 to n mapping of work requests and sges */
    struct swr_list_info    *persist_wrnodes ____cacheline_aligned;
    struct recv_bufinfo     recv_bufinfo ____cacheline_aligned;

    /* publication list for the wce for send and receives */
    /*
     * used or set bits for wrs for send and receive
     * 0 -> data is not yet posted
     * 1 -> data has been posted but not removed
     */
    uint8_t                 *persist_cq_bits ____cacheline_aligned;
    uint8_t                 *recv_cq_bits ____cacheline_aligned;

    /* common buffer that will be used by the writes */
    uint8_t                 *common_buffer ____cacheline_aligned;

    int                     persist_with_reads;

    /* total recv wrs */
    uint64_t                total_flush_wrs;
    uint64_t                total_persist_wrs;
    uint64_t                total_recv_wrs;
    uint64_t                pt_flush_wrs;
    uint64_t                pt_persist_wrs;
    uint64_t                pt_recv_wrs;

#ifdef DPRINT
    struct pm_stats         stats;
#endif
} pmrep_ctx_t ____cacheline_aligned;

int setup_region_client(pmrep_ctx_t *pctx, uint8_t *buffer, size_t buffer_size,
                        int num_threads, int persist_with_reads);
void clear_region(pmrep_ctx_t *pctx, int free_buffer);

void flush_data_simple(pmrep_ctx_t *pctx, void *addr,
                       size_t bytes, int lazy_write, int thread_id);
void persist_data_wread(pmrep_ctx_t *pctx, int thread_id);
void persist_data_wsend(pmrep_ctx_t *pctx, persistence_t pt, int thread_id);
void persist_data_with_complex_writes(pmrep_ctx_t *pctx, persistence_t pt,
                                      int thread_id);

/* server side */
int setup_region_server(pmrep_ctx_t *pctx);

char *get_value(int value, struct error_name *name_array,
                char *data, size_t size);
char *get_pt_name(persistence_t pt, char *data);
char *get_wr_status_name(int status, char *data, size_t size);
char *get_cm_event_name(int event, char *data, size_t size);

#endif /* __REP_SUBSTRATE_H_ */
