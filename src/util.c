#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>

#include <sched.h>
#include <time.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>

#include "arch.h"
#include "util.h"

void die(const char *err_str, ...)
{
    va_list ap;

    va_start(ap, err_str);
    vfprintf(stderr, err_str, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    exit(EXIT_FAILURE);
}

void edie(const char *err_str, ...)
{
    va_list ap;

    va_start(ap, err_str);
    vfprintf(stderr, err_str, ap);
    va_end(ap);
    fprintf(stderr, "%s\n", strerror(errno));
    exit(EXIT_FAILURE);
}

uint32_t inline rand32(uint32_t *seed)
{
    *seed = *seed * 1103515243 + 12345;
    return  *seed & 0x7ffffffff;
}

void setaffinity(int core)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);
    if (sched_setaffinity(0, sizeof(cpuset), &cpuset) < 0)
        edie("setaffinity, sched_setaffinity failed");
}

uint64_t usec(void)
{
    struct timeval tv;
    gettimeofday(&tv, 0);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

int parse_options(int argc, char *argv[], struct cmd_opt *opt)
{
    static struct option options[] = {
        {"server",              required_argument, 0, 's'},
        {"port",                required_argument, 0, 'p'},
        {"iters",               required_argument, 0, 'j'},
        {"buffer_size",         required_argument, 0, 'b'},
        {"enable_inlining",     required_argument, 0, 'i'},
        {"enable_wpst",         required_argument, 0, 'c'},
        {"enable_spst",         required_argument, 0, 'm'},
        {"write_batch",         required_argument, 0, 'w'},
        {"lazy_writes",         required_argument, 0, 'l'},
        {0,             0,                 0, 0},
    };
    int arg_cnt;

    for (arg_cnt = 0; 1; ++arg_cnt) {
        int c, idx = 0;
        c = getopt_long(argc, argv,
                        "s:p:j:b:i:c:m:w:l:", options, &idx);
        if (c == -1)
            break;
        switch(c) {
        case 's':
            opt->server_ip = optarg;
            break;
        case 'p':
            opt->tcp_conn_port = optarg;
            break;
        case 'j':
            opt->iterations = atoi(optarg);
            break;
        case 'b':
            opt->buffer_size = atol(optarg);
            break;
        case 'i':
            opt->allow_inlined_data = atoi(optarg)?1:0;
            break;
        case 'c':
            opt->enable_weak_persistence = atoi(optarg)?1:0;
            break;
        case 'm':
            opt->enable_strong_persistence = atoi(optarg)?1:0;
            break;
        case 'w':
            opt->write_batch_count = atoi(optarg)?atoi(optarg):1;
            break;
        case 'l':
            opt->enable_lazy_writes = atoi(optarg)?1:0;
            break;
        default:
            return -EINVAL;
        }
    }
    return arg_cnt;
}

void usage(FILE *out, char *progname)
{
    fprintf(out, "Usage: %s\n", progname);
    fprintf(out, "  --server    = Server ip for the client\n");
    fprintf(out, "  --port      = Server port for the client\n");
    fprintf(out, "  --iters     = number of jobs / iterations\n");
    fprintf(out, "  --buffer_size = buffer size\n");
    fprintf(out, "  --enable_inlining = Enable inlined data\n");
    fprintf(out, "  --enable_wpst = Enable weak persistence (300ns)\n");
    fprintf(out, "  --enable_spst = Enable strong persistence (2usec)\n");
    fprintf(out, "  --write_batch = Multiple writes before persisting\n");
    fprintf(out, "  --lazy_writes = Post all writes in one shot\n");
}

void *mem_alloc(size_t alignment, size_t size, char *str)
{
    void *buffer = NULL;
    int ret;

    ret = posix_memalign((void **)&buffer, alignment, size);
    if (buffer == NULL) {
        fprintf(stderr, "posix_memalign failed for %s with error %s\n",
                str, strerror(ret));
        return NULL;
    }
    memset(buffer, 0, size);
    return buffer;
}
void *mem_alloc_pgalign(size_t size, char *str)
{
    return mem_alloc(PAGE_SIZE, size, str);
}
void *mem_alloc_l3align(size_t size, char *str)
{
    return mem_alloc(L1D_CACHELINE_BYTES, size, str);
}

uint64_t gethrtime(void)
{
    struct timespec tp;
    tp.tv_sec = 0;
    tp.tv_nsec = 0;

    clock_gettime(CLOCK_MONOTONIC, &tp);

    return (tp.tv_sec * 1000000000LL) + tp.tv_nsec;
}

size_t server_setget_info(int port)
{
    struct sockaddr_in serv_addr;
    int lfd = 0, ret = 0, connfd;
    size_t buffer_size;
    int conn_port = 20480;

    lfd = socket(AF_INET, SOCK_STREAM, 0);
    assert(lfd);

    memset(&serv_addr, 0, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(conn_port);

    ret = bind(lfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
    assert(ret == 0);

    ret = listen(lfd, 1);
    assert(ret == 0);


    connfd = accept(lfd, (struct sockaddr *)NULL, NULL);
    assert(connfd);

    ret = write(connfd, &port, sizeof(port));
    assert(ret == sizeof(port));

    ret = read(connfd, &buffer_size, sizeof(buffer_size));
    assert(ret == sizeof(buffer_size));

    close(connfd);
    close(lfd);

    return buffer_size;
}

int client_getset_info(size_t buffer_size, const char *server_ip)
{
    int sfd = 0;
    int port = 20480;
    int ret = 0;
    struct sockaddr_in serv_addr;

    sfd = socket(AF_INET, SOCK_STREAM, 0);
    assert(sfd);

    memset(&serv_addr, 0, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    ret = inet_pton(AF_INET, server_ip, &serv_addr.sin_addr);
    assert(ret >= 0);

    ret = connect(sfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    assert(ret == 0);

    ret = read(sfd, &port, sizeof(port));
    assert(ret == sizeof(port));

    ret = write(sfd, &buffer_size, sizeof(buffer_size));
    assert(ret == sizeof(buffer_size));

    close(sfd);
    return port;
}

inline void spinlock_init(struct mcslock_t *lock)
{
	lock->qnode = NULL;
	smp_wmb_tso();
}

inline void spin_lock(struct mcslock_t *lock, struct mcsqnode_t *qnode)
{
    struct mcsqnode_t *prev;

    qnode->locked = 1;
    qnode->next = NULL;
    smp_wmb();

    prev = (struct mcsqnode_t *)smp_swap(&lock->qnode, qnode);
    if (prev) {
        prev->next = qnode;
        smp_wmb();
        while(qnode->locked) ;
    }
}

inline void spin_unlock(struct mcslock_t *lock, struct mcsqnode_t *qnode)
{
    if (!qnode->next) {
        if (smp_cas(&lock->qnode, qnode, NULL))
            return;
        while (!qnode->next) smp_rmb();
    }
    qnode->next->locked = 0;
    smp_wmb();
}
