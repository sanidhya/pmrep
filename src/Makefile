CC := gcc
CFLAGS  := -Wall -Werror #-fno-strict-aliasing
LDLIBS  := ${LDLIBS} -lrdmacm -libverbs -lpthread #-lgsl -lgslcblas -lm
CFLAGS += -Iinclude

ifeq ($(DEBUG),1)
	FLAGS = -O0 -DDPRINT -g -fno-inline
else
	FLAGS = -O3
endif
CFLAGS += $(FLAGS)

APPS := client_rd server_rd client_wr_rd client_wr_sd server_sd
BIN := util.o rep_substrate.o

all: ${APPS}

client_rd: ${BIN}

server_rd: ${BIN}

client_wr_rd: ${BIN}

client_wr_sd: ${BIN}

server_sd: ${BIN}

clean:
	rm -f ${APPS} ${BIN}

.PHONY: clean all
