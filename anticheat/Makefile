CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11 -pthread -fPIC
LDFLAGS ?= -pthread -lm

# Optional eBPF kernel monitor (requires libbpf). Detect it at build time so
# the project still builds on hosts without libbpf: in that case ebpf_monitor.c
# compiles to a graceful no-op that falls back to the user-mode protections.
LIBBPF_CFLAGS :=
LIBBPF_LIBS    :=
EBPF_PROG_SRC  :=
# ebpf_monitor.c is ALWAYS compiled: it provides the graceful [INFO] fallback
# stubs when libbpf is absent, and api.c/main.c always reference it.
EBPF_MON_SRC  := src/ebpf_monitor.c

ifneq ($(shell pkg-config --exists libbpf 2>/dev/null && echo yes),)
    LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
    LIBBPF_LIBS   := $(shell pkg-config --libs libbpf)
    EBPF_PROG_SRC := src/ebpf_program.c
    CFLAGS        += -DHAVE_LIBBPF
endif

# All sources (including the shared-library API wrapper and network engine).
SRC := src/main.c src/report.c src/debugger.c src/scanner.c src/integrity.c \
       src/sha256.c src/memguard.c src/envguard.c src/telemetry.c \
       src/api.c src/network.c $(EBPF_MON_SRC) $(EBPF_PROG_SRC)

# Objects for the standalone binary (keeps main() out of the shared library).
OBJ := $(SRC:.c=.o)

# Objects for the shared library (everything except the CLI entry point).
LIBSRC := $(filter-out src/main.c,$(SRC))
LIBOBJ := $(LIBSRC:.c=.o)

BIN := anticheat
LIB := libanticheat.so

all: $(BIN) $(LIB)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS) $(LIBBPF_LIBS)

$(LIB): $(LIBOBJ)
	$(CC) -shared $(CFLAGS) -o $@ $(LIBOBJ) $(LDFLAGS) $(LIBBPF_LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(LIBOBJ) $(BIN) $(LIB) tests/network_stress

.PHONY: all clean test

# Stress / robustness tests for the authenticated UDP network engine.
tests/network_stress: tests/network_stress.c src/network.c src/sha256.c
	$(CC) $(CFLAGS) -Isrc -o $@ tests/network_stress.c \
	       src/network.c src/sha256.c $(LDFLAGS)

test: tests/network_stress
	./tests/network_stress
	python3 -m unittest tests.test_dashboard
