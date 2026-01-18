CC ?= cc
CFLAGS ?= -O2 -g -Wall -Wextra -Wshadow -Wformat=2 -Wundef -Wpointer-arith -Wcast-qual -Wstrict-prototypes -std=c11
CPPFLAGS ?= -Iinclude
LDFLAGS ?=
LDLIBS ?=

BIN := xtop
SRCS := \
	src/main.c \
	src/proc_stat.c \
	src/proc_mem.c \
	src/proc_proc.c \
	src/fmt.c

OBJS := $(SRCS:.c=.o)

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(BIN) $(OBJS)
