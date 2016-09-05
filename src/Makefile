CC := gcc
CFLAGS  := -Wall -Werror -fno-strict-aliasing
LDLIBS  := ${LDLIBS} -lrdmacm -libverbs -lpthread #-lgsl -lgslcblas -lm
CFLAGS += -Iinclude

ifeq ($(DEBUG),1)
	FLAGS = -O0 -DDPRINT -g -fno-inline
else
	FLAGS = -O3
endif
CFLAGS += $(FLAGS)

APPS := client_rd server_rd
BIN := util.o rep_substrate.o

all: ${APPS}

client_rd: ${BIN}

server_rd: ${BIN}

clean:
	rm -f ${APPS} ${BIN}

.PHONY: clean all
