#ifndef MEMGUARD_H
#define MEMGUARD_H

#include <stdatomic.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "report.h"
#include "sha256.h"

#define MEMGUARD_MAX_REGIONS 8

typedef struct {
    uintptr_t start;
    size_t size;
    unsigned char baseline[SHA256_DIGEST_LEN];
    int dirty;
} memguard_region_t;

typedef struct {
    char exe_path[4096];
    memguard_region_t regions[MEMGUARD_MAX_REGIONS];
    size_t region_count;
    int interval_ms;
    int started;
    reporter_t *rep;
    atomic_int violations;
    atomic_bool stop;
    atomic_bool running;
    pthread_t thread;
} memguard_t;

int memguard_init(memguard_t *mg, int interval_ms, reporter_t *rep);
int memguard_check_once(memguard_t *mg, reporter_t *rep);
int memguard_start(memguard_t *mg);
void memguard_stop(memguard_t *mg);
int memguard_violations(const memguard_t *mg);
int memguard_selftest(memguard_t *mg, reporter_t *rep);

#endif
