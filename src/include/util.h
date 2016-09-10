#define _GNU_SOURCE
#ifndef __UTIL_H_
#define __UTIL_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <getopt.h>

#include <sched.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include <stdarg.h>

#include "arch.h"

#define pm_here() fprintf(stderr, "[RePM-HERE:%s%d] <== \n", __func__, __LINE__)

#ifdef DPRINT
#define dprintf(__fmt, ...) do {                                               \
    fprintf(stderr, "[DBG: %s: %d] " __fmt, __func__, __LINE__, ##__VA_ARGS__);\
    } while (0)
#else
#define dprintf(__fmt, ...) do { } while(0)
#endif

#define get_time_diff(tv1, tv2)                                                \
(((tv2.tv_sec) - (tv1.tv_sec)) * 1000000000 + (tv2.tv_nsec) - (tv1.tv_nsec))

#define get_diff_jobs(v, start, end, div)           \
do {                                                \
    v = (double)((end).tv_sec - (start).tv_sec);    \
    v = (v) * 1000000000;                           \
    v += end.tv_nsec - start.tv_nsec;               \
    v /= (double)(div);                             \
} while (0)

#define __noret__ __attribute__((noreturn))

#define MSYNC_OVERHEAD  (2000) /* nanoseconds */

struct error_name {
    int value;
    char *name;
};

typedef enum {
    NO_PERSISTENCE_DDIO,
    NO_PERSISTENCE_NODDIO,
    WEAK_PERSISTENCE_WITH_ADR_DDIO,
    WEAK_PERSISTENCE_WITH_ADR_NODDIO,
    WEAK_PERSISTENCE_WITH_eADR_DDIO,
    WEAK_PERSISTENCE_WITH_eADR_NODDIO,
    STRONG_PERSISTENCE_WITH_ADR_DDIO,
    STRONG_PERSISTENCE_WITH_ADR_NODDIO,
    STRONG_PERSISTENCE_WITH_eADR_DDIO,
    STRONG_PERSISTENCE_WITH_eADR_NODDIO,
    NUM_PERSISTENCE,
} persistence_t;

void __noret__ die(const char *err_str, ...);
void __noret__ edie(const char *err_str, ...);

void setaffinity(int core);
uint64_t usec(void);
uint32_t rand32(uint32_t *seed);

struct cmd_opt {
    char        *server_ip;
    char        *tcp_conn_port;
    int         num_threads;
    uint32_t    iterations;
    size_t      buffer_size;
    int         allow_inlined_data;
    /* always use pmem in this case */
    int         enable_weak_persistence;
    int         enable_strong_persistence;
    /* enable batching of the writes */
    int         write_batch_count;
    /* enable posting of multiple writes together */
    int         enable_lazy_writes;
    /* runningt time between flushes */
    uint64_t    flush_latency;
    /* every commit gap */
    uint64_t    commit_latency;
    /* if the card is on different socket, then add this factor */
    int         const_cores;
    /* persistence */
    int         pt;
    /* max cores allowed to run on the server side */
    int         max_cores;
};

extern struct error_name persistence_type[];

void burn_cycles(uint64_t cycles);

int parse_options(int argc, char *argv[], struct cmd_opt *opt);
void usage(FILE *out, char *progname);

void *mem_alloc(size_t alignment, size_t size, char *str);
void *mem_alloc_pgalign(size_t size, char *str);
void *mem_alloc_l3align(size_t size, char *str);

int file_exists(const char *filename);
uint64_t gethrtime(void);

/*
 * will send the port info to the client side and will get the
 * buffer size info back from the client
 */
size_t server_setget_info(int port, int *num_threads, int *persist_with_reads);
/*
 * will get the port info and send the buffer size info
 */
int client_getset_info(size_t buffer_size, const char *server_ip,
                       int num_threads, int persist_with_reads);


/* msync and clflush cost */
void msync_overhead(void);
void clflushopt_overhead(size_t size);

/* mcs lock implementation */
struct mcsqnode_t {
	volatile int locked;
	struct mcsqnode_t *next;
};

struct mcslock_t {
	volatile struct mcsqnode_t *qnode;
};

void spinlock_init(struct mcslock_t *lock);
void spin_lock(struct mcslock_t *lock, struct mcsqnode_t *qnode);
void spin_unlock(struct mcslock_t *lock, struct mcsqnode_t *qnode);

#endif /* __UTIL_H_ */
