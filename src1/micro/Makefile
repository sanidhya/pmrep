CC := gcc
CFLAGS  := -Wall -Werror -fno-strict-aliasing
LDLIBS  := ${LDLIBS} -lrdmacm -libverbs -lpthread
CFLAGS += -Iinclude
# IBVCONF = include/config.h

DEBUG=1
ifeq ($(DEBUG),1)
	FLAGS = -O0 -DDPRINT -g -fno-inline
else
	FLAGS = -O3
endif
CFLAGS += $(FLAGS)

APPS := server_clwrites client_clwrites

LIBSRC = lib/util.c lib/rdma_substrate.c
LIB = $(patsubst %.c, %.o, $(LIBSRC))

all: $(APPS)

# conf: $(IBVCONF)

server_clwrites: $(LIB)

client_clwrites: $(LIB)

# %.o: lib/%.c $(conf)
%.o: lib/%.c
	$(CC) $(CFLAGS) -c -o $@ $^

# include/config.h: getdevinfo.py
# 	python $^ > $@

clean:
	rm -f $(APPS) $(LIB)

tags:
	@ctags * -R

cscope:
	@find . -name '*.[h|c]' > cscope.files
	@cscope -b -q -k

distclean: clean
	rm -f tags cscope.*

.PHONY: clean all
