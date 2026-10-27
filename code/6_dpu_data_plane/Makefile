CC ?= cc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra
all: dpu_model
dpu_model: main.c dpu.c dpu.h
	$(CC) $(CFLAGS) -o $@ main.c dpu.c
clean:
	rm -f dpu_model
.PHONY: all clean
