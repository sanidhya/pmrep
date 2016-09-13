CC := gcc
CFLAGS  := -Wall -Werror -fno-strict-aliasing
LDLIBS  := ${LDLIBS} -lrdmacm -libverbs -lpthread
CFLAGS += -Iinclude
IBVCONF = include/config.h

ifeq ($(DEBUG),1)
	FLAGS = -O0 -DDPRINT -g -fno-inline
else
	FLAGS = -O3
endif
CFLAGS += $(FLAGS)

APPS := server_rd client_wr_rd client_wr_sd server_sd server_wr

LIBSRC = lib/util.c lib/rep_substrate.c
LIB = $(patsubst %.c, %.o, $(LIBSRC))

all: $(APPS) $(IBVCONF)

conf: $(IBVCONF)

client_rd: $(LIB)

server_rd: $(LIB)

client_wr_rd: $(LIB)

client_wr_sd: $(LIB)

server_sd: $(LIB)

server_wr: $(LIB)

%.o: lib/%.c $(conf)
	$(CC) $(CFLAGS) -c -o $@ $^

include/config.h: getdevinfo.py
	python $^ > $@

clean:
	rm -f $(APPS) $(LIB) include/config.h

.PHONY: clean all
