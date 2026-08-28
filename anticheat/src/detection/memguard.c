#define _GNU_SOURCE

#include "memguard.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "sha256.h"

#define CHUNK_MAX (1u << 20)

static void hash_memory(const void *data, size_t len,
                        unsigned char digest[SHA256_DIGEST_LEN]) {
    const unsigned char *p = (const unsigned char *)data;
    sha256_ctx ctx;
    sha256_init(&ctx);
    size_t remaining = len;
    while (remaining > 0) {
        size_t chunk = remaining > CHUNK_MAX ? CHUNK_MAX : remaining;
        sha256_update(&ctx, p, chunk);
        p += chunk;
        remaining -= chunk;
    }
    sha256_final(&ctx, digest);
}

static int find_exe_path(memguard_t *mg) {
    ssize_t n = readlink("/proc/self/exe", mg->exe_path,
                         sizeof(mg->exe_path) - 1);
    if (n <= 0) {
        return -1;
    }
    mg->exe_path[n] = '\0';
    return 0;
}

static int parse_regions(memguard_t *mg) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) {
        return -1;
    }

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        unsigned long start, end;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) != 3) {
            continue;
        }
        if (!strchr(perms, 'x')) {
            continue;
        }
        const char *path = strchr(line, '/');
        if (!path) {
            continue;
        }
        size_t plen = strcspn(path, "\n");
        if (plen != strlen(mg->exe_path) ||
            strncmp(path, mg->exe_path, plen) != 0) {
            continue;
        }
        if (mg->region_count >= MEMGUARD_MAX_REGIONS) {
            break;
        }

        memguard_region_t *r = &mg->regions[mg->region_count++];
        r->start = (uintptr_t)start;
        r->size = (size_t)(end - start);
        hash_memory((const void *)r->start, r->size, r->baseline);
    }
    fclose(f);

    return mg->region_count > 0 ? 0 : -1;
}

static int verify_regions(memguard_t *mg, reporter_t *rep) {
    int newly_dirty = 0;

    for (size_t i = 0; i < mg->region_count; i++) {
        memguard_region_t *r = &mg->regions[i];
        unsigned char cur[SHA256_DIGEST_LEN];
        hash_memory((const void *)r->start, r->size, cur);

        if (memcmp(cur, r->baseline, SHA256_DIGEST_LEN) != 0) {
            if (!r->dirty) {
                r->dirty = 1;
                newly_dirty++;
                char detail[256];
                snprintf(detail, sizeof(detail),
                         "region %zu @ 0x%lx size=%zu",
                         i, (unsigned long)r->start, r->size);
                report_add(rep, SEV_CRITICAL, "memguard",
                           "live memory modification detected in own code segment",
                           detail);
            }
        } else if (r->dirty) {
            r->dirty = 0;
            report_add(rep, SEV_INFO, "memguard",
                       "code segment restored to baseline", NULL);
        }
    }

    return newly_dirty;
}

int memguard_init(memguard_t *mg, int interval_ms, reporter_t *rep) {
    memset(mg, 0, sizeof(*mg));
    mg->interval_ms = interval_ms > 0 ? interval_ms : 250;
    mg->rep = rep;
    atomic_store(&mg->stop, false);
    atomic_store(&mg->violations, 0);
    atomic_store(&mg->running, false);

    if (find_exe_path(mg) != 0) {
        report_add(rep, SEV_HIGH, "memguard",
                   "cannot resolve own executable path", strerror(errno));
        return -1;
    }
    if (parse_regions(mg) != 0) {
        report_add(rep, SEV_HIGH, "memguard",
                   "cannot locate executable code segment in /proc/self/maps",
                   mg->exe_path);
        return -1;
    }

    char detail[256];
    snprintf(detail, sizeof(detail),
             "regions=%zu code@0x%lx size=%zu",
             mg->region_count,
             (unsigned long)mg->regions[0].start,
             mg->regions[0].size);
    report_add(rep, SEV_INFO, "memguard",
               "baseline hash generated for own code segment", detail);
    return 0;
}

int memguard_check_once(memguard_t *mg, reporter_t *rep) {
    int n = verify_regions(mg, rep);
    if (n > 0) {
        atomic_fetch_add(&mg->violations, n);
    }
    return n;
}

static void *monitor_routine(void *arg) {
    memguard_t *mg = (memguard_t *)arg;
    atomic_store(&mg->running, true);

    struct timespec tick = {0, 50 * 1000000L};
    while (!atomic_load(&mg->stop)) {
        memguard_check_once(mg, mg->rep);

        int elapsed = 0;
        while (elapsed < mg->interval_ms && !atomic_load(&mg->stop)) {
            nanosleep(&tick, NULL);
            elapsed += 50;
        }
    }

    atomic_store(&mg->running, false);
    return NULL;
}

int memguard_start(memguard_t *mg) {
    if (mg->started) {
        return 0;
    }
    int rc = pthread_create(&mg->thread, NULL, monitor_routine, mg);
    if (rc != 0) {
        errno = rc;
        report_add(mg->rep, SEV_HIGH, "memguard",
                   "cannot start monitor thread", strerror(errno));
        return -1;
    }
    mg->started = 1;
    return 0;
}

void memguard_stop(memguard_t *mg) {
    atomic_store(&mg->stop, true);
    if (mg->started) {
        pthread_join(mg->thread, NULL);
    }
    mg->started = 0;
}

int memguard_violations(const memguard_t *mg) {
    return atomic_load(&mg->violations);
}

int memguard_selftest(memguard_t *mg, reporter_t *rep) {
    if (mg->region_count == 0) {
        report_add(rep, SEV_HIGH, "memguard",
                   "selftest: no code region available to patch", NULL);
        return -1;
    }

    const memguard_region_t *r = &mg->regions[0];
    unsigned char *patch_at = (unsigned char *)(r->start + r->size - 4);

    if (mprotect((void *)r->start, r->size,
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        report_add(rep, SEV_HIGH, "memguard", "selftest: mprotect failed",
                   strerror(errno));
        return -1;
    }

    unsigned char orig = patch_at[0];
    patch_at[0] = (unsigned char)(orig ^ 0xff);
    report_add(rep, SEV_INFO, "memguard",
               "selftest: patched a byte in own code segment (simulated attack)",
               NULL);

    sleep(2);

    patch_at[0] = orig;
    mprotect((void *)r->start, r->size, PROT_READ | PROT_EXEC);
    report_add(rep, SEV_INFO, "memguard", "selftest: byte restored", NULL);
    return 0;
}
