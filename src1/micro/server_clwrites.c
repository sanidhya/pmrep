#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <string.h>
#include <signal.h>

#include "rdma_substrate.h"
#include "util.h"

static rep_ctx_t pctx;

void handler(int sig)
{
    clear_region(&pctx, 1);
    exit(0);
}

int main(int argc, char *argv[])
{
    struct cmd_opt opt = {"192.168.0.1", 0, 0, 1000, 0, 0};

    setaffinity(opt.const_cores + 0);

    if (parse_options(argc, argv, &opt) < 0) {
        usage(stderr, argv[0]);
        return -1;
    }

    signal(SIGINT, handler);

    memset(&pctx, 0, sizeof(pctx));
    setup_region_server(&pctx);

    while (1);


    return 0;
}
