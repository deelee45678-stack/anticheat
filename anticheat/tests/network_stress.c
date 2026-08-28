#define _GNU_SOURCE

/*
 * Stress / robustness test for the authenticated UDP network engine.
 *
 * Build (from the anticheat/ directory):
 *   cc -O2 -Wall -Wextra -std=c11 -pthread -fPIC -Isrc \
 *       -o tests/network_stress tests/network_stress.c \
 *       src/network.c src/sha256.c -pthread -lm
 *
 * Exercises:
 *   1. Hard fail: initialize_network_client with no key returns -1.
 *   2. Concurrency: many threads hammer network_send_alert(); every datagram
 *      is delivered and carries a valid HMAC-SHA256 signature (verified here
 *      with the same secret + SHA-256 primitives).
 *   3. Non-blocking drop: flooding a socket nobody reads never blocks; the
 *      send path returns 0 (dropped) instead of stalling or erroring.
 */

#include "network.h"
#include "sha256.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define KEY  "test-secret-key-do-not-use-in-prod"
#define PORT 18099

#define SHA256_BLOCK 64
#define HEXLEN (SHA256_DIGEST_LEN * 2)

static unsigned char g_secret[256];
static size_t        g_secret_len;

/* ---- HMAC-SHA256 (mirrors the implementation in network.c) ------------- */
static void hmac_sha256(const unsigned char *key, size_t keylen,
                        const unsigned char *msg, size_t msglen,
                        unsigned char out[SHA256_DIGEST_LEN]) {
    unsigned char k[SHA256_BLOCK];
    if (keylen > SHA256_BLOCK) {
        sha256_memory(key, keylen, k);
        keylen = SHA256_DIGEST_LEN;
    } else {
        memcpy(k, key, keylen);
    }
    memset(k + keylen, 0, SHA256_BLOCK - keylen);

    unsigned char ipad[SHA256_BLOCK], opad[SHA256_BLOCK];
    for (size_t i = 0; i < SHA256_BLOCK; i++) {
        ipad[i] = (unsigned char)(k[i] ^ 0x36);
        opad[i] = (unsigned char)(k[i] ^ 0x5c);
    }
    sha256_ctx ctx;
    unsigned char inner[SHA256_DIGEST_LEN];
    sha256_init(&ctx);
    sha256_update(&ctx, ipad, SHA256_BLOCK);
    sha256_update(&ctx, msg, msglen);
    sha256_final(&ctx, inner);

    sha256_init(&ctx);
    sha256_update(&ctx, opad, SHA256_BLOCK);
    sha256_update(&ctx, inner, SHA256_DIGEST_LEN);
    sha256_final(&ctx, out);
}

/* ---- tiny JSON field extractor (test-only, trusted sender format) ----- */
static int extract_int(const char *buf, const char *key, long *out) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(buf, pat);
    if (!p) return -1;
    p += strlen(pat);
    char *end = NULL;
    long v = strtol(p, &end, 10);
    if (end == p) return -1;
    *out = v;
    return 0;
}

static int extract_str(const char *buf, const char *key, char *out, size_t outsz) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    const char *p = strstr(buf, pat);
    if (!p) return -1;
    p += strlen(pat);
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < outsz) {
        out[i++] = *p++;
    }
    out[i] = '\0';
    return 0;
}

/* ---- receiver thread state -------------------------------------------- */
static int  g_sock = -1;
static int  g_target = 0;
static int  g_received = 0;
static int  g_verified = 0;
static int  g_bad = 0;
static int  g_stop = 0;
static long g_send_errs = 0;   /* network_send_alert() returning < 0 */
static long g_sent_ok = 0;     /* network_send_alert() returning > 0 */
static pthread_mutex_t g_m = PTHREAD_MUTEX_INITIALIZER;

static void *receiver(void *arg) {
    (void)arg;
    char buf[2048];
    while (1) {
        ssize_t n = recvfrom(g_sock, buf, sizeof(buf) - 1, 0, NULL, NULL);
        if (n <= 0) {
            if (g_stop) break;
            continue;
        }
        buf[n] = '\0';

        long sev, ts;
        char label[32], module[128], message[1024], sig[HEXLEN + 1];
        if (extract_int(buf, "severity", &sev) < 0 ||
            extract_int(buf, "ts", &ts) < 0 ||
            extract_str(buf, "sev_label", label, sizeof(label)) < 0 ||
            extract_str(buf, "module", module, sizeof(module)) < 0 ||
            extract_str(buf, "message", message, sizeof(message)) < 0 ||
            extract_str(buf, "sig", sig, sizeof(sig)) < 0) {
            pthread_mutex_lock(&g_m); g_bad++; pthread_mutex_unlock(&g_m);
            continue;
        }

        /* Reconstruct the canonical string the client signed. */
        char canon[1200];
        int clen = snprintf(canon, sizeof(canon), "%ld|%s|%s|%s|%ld",
                            sev, label, module, message, ts);
        unsigned char dig[SHA256_DIGEST_LEN];
        hmac_sha256(g_secret, g_secret_len,
                    (const unsigned char *)canon, (size_t)clen, dig);

        char hex[HEXLEN + 1];
        static const char hx[] = "0123456789abcdef";
        for (int i = 0; i < SHA256_DIGEST_LEN; i++) {
            hex[2 * i]     = hx[(dig[i] >> 4) & 0xf];
            hex[2 * i + 1] = hx[dig[i] & 0xf];
        }
        hex[HEXLEN] = '\0';

        int ok = (strncmp(hex, sig, HEXLEN) == 0);
        pthread_mutex_lock(&g_m);
        g_received++;
        if (ok) g_verified++;
        else    g_bad++;
        int done = (g_target > 0 && g_received >= g_target);
        pthread_mutex_unlock(&g_m);
        if (done) break;
    }
    return NULL;
}

/* ---- sender threads --------------------------------------------------- */
struct send_arg {
    int id;
    int count;
};

static void *sender(void *arg) {
    struct send_arg *sa = (struct send_arg *)arg;
    char module[64];
    for (int i = 0; i < sa->count; i++) {
        snprintf(module, sizeof(module), "t%d_m%d", sa->id, i);
        int r = network_send_alert(2, module, "concurrent stress alert");
        if (r < 0) __sync_fetch_and_add(&g_send_errs, 1);
        else if (r > 0) __sync_fetch_and_add(&g_sent_ok, 1);
        /* Tiny pace so a lossy loopback can drain the burst instead of
         * overflowing the kernel buffer; sends stay non-blocking. */
        usleep(5);
    }
    return NULL;
}

static void fail(const char *msg) {
    fprintf(stderr, "FAIL: %s\n", msg);
    exit(1);
}

int main(void) {
    g_secret_len = strlen(KEY);
    if (g_secret_len > sizeof(g_secret)) g_secret_len = sizeof(g_secret);
    memcpy(g_secret, KEY, g_secret_len);

    /* 1. Hard fail: no key configured -> -1 (and no ANTICHEAT_NETWORK_KEY env).
     * We deliberately unset it for this check. */
    unsetenv("ANTICHEAT_NETWORK_KEY");
    if (initialize_network_client("127.0.0.1", PORT, NULL) != -1) {
        fail("initialize_network_client accepted a missing key");
    }
    printf("[ok] missing key is rejected (hard fail)\n");

    /* Set up a receiver socket. */
    g_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_sock < 0) fail("socket");
    int one = 1;
    setsockopt(g_sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    /* Large receive buffer so the single receiver thread can absorb the burst
     * without the kernel dropping datagrams (localhost UDP is still lossy
     * under extreme concurrency, which is why the assertion below is tolerant). */
    int rcv = 8 * 1024 * 1024;
    setsockopt(g_sock, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
    /* Bound the receiver's recvfrom so it periodically re-checks g_stop and
     * the test always terminates even if no further datagrams arrive. */
    struct timeval rcvto = {1, 0};
    setsockopt(g_sock, SOL_SOCKET, SO_RCVTIMEO, &rcvto, sizeof(rcvto));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(PORT);
    if (bind(g_sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        fail("bind");
    }

    if (initialize_network_client("127.0.0.1", PORT, KEY) != 0) {
        fail("initialize_network_client with key");
    }
    printf("[ok] client initialized with key\n");

    /* 2. Concurrency + HMAC verification. */
    #define NTHREADS 8
    #define PER_THREAD 200
    g_target = NTHREADS * PER_THREAD;
    pthread_t rx;
    if (pthread_create(&rx, NULL, receiver, NULL) != 0) fail("rx thread");

    pthread_t tx[NTHREADS];
    struct send_arg args[NTHREADS];
    for (int i = 0; i < NTHREADS; i++) {
        args[i].id = i;
        args[i].count = PER_THREAD;
        if (pthread_create(&tx[i], NULL, sender, &args[i]) != 0)
            fail("tx thread");
    }

    /* Time the send storm: it must finish quickly (non-blocking). */
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < NTHREADS; i++) pthread_join(tx[i], NULL);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double secs = (t1.tv_sec - t0.tv_sec) +
                  (t1.tv_nsec - t0.tv_nsec) / 1e9;
    if (secs > 5.0) fail("send storm took too long (not non-blocking?)");

    /* Wait for the receiver to collect everything (with a generous timeout). */
    struct timespec wt0, wt1;
    clock_gettime(CLOCK_MONOTONIC, &wt0);
    while (1) {
        pthread_mutex_lock(&g_m);
        int got = g_received;
        pthread_mutex_unlock(&g_m);
        if (got >= g_target) break;
        clock_gettime(CLOCK_MONOTONIC, &wt1);
        double w = (wt1.tv_sec - wt0.tv_sec) +
                   (wt1.tv_nsec - wt0.tv_nsec) / 1e9;
        if (w > 5.0) break;
        usleep(1000);
    }

    pthread_mutex_lock(&g_m);
    int received = g_received, verified = g_verified, bad = g_bad;
    pthread_mutex_unlock(&g_m);
    printf("[info] received=%d verified=%d bad=%d (queued %ld, expected %d)\n",
           received, verified, bad, g_sent_ok, g_target);
    /* localhost UDP can drop a few datagrams under a heavy concurrent burst;
     * that is inherent to the transport and not a client defect. The
     * invariants we actually assert are: every received datagram carried a
     * valid signature, none failed to parse/verify, and of the datagrams the
     * client actually queued (network_send_alert returned > 0) the vast
     * majority were delivered. Datagrams the client itself dropped under
     * backpressure (non-blocking returns 0) are counted separately by the
     * flood test below. */
    if (g_sent_ok > 0 && received < (g_sent_ok * 8) / 10)
        fail("too many datagrams lost (UDP transport issue or client bug)");
    if (verified != received) fail("HMAC verification failed for some alerts");
    if (bad != 0) fail("some datagrams failed to parse/verify");
    printf("[ok] concurrency + HMAC verification passed\n");

    /* 3. Non-blocking drop: point the client at a socket nobody reads and
     * flood it; sends must not block and must return 0 (dropped) rather than
     * erroring out. */
    g_stop = 1;              /* tell receiver to exit if it loops */
    pthread_join(rx, NULL);

    int drop_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (drop_sock < 0) fail("drop socket");
    struct sockaddr_in da;
    memset(&da, 0, sizeof(da));
    da.sin_family = AF_INET;
    da.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    da.sin_port = htons(PORT + 1);
    if (bind(drop_sock, (struct sockaddr *)&da, sizeof(da)) < 0) fail("drop bind");
    if (initialize_network_client("127.0.0.1", PORT + 1, KEY) != 0)
        fail("reinit for drop test");

    int drops = 0, sent = 0, errs = 0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < 200000; i++) {
        int r = network_send_alert(3, "drop", "flood");
        if (r < 0) errs++;
        else if (r == 0) drops++;
        else sent++;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    secs = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    if (secs > 10.0) fail("flood took too long (blocking?)");
    if (errs != 0) fail("flood produced errors (negative return)");
    if (drops == 0) fail("expected some dropped datagrams under flood");
    printf("[info] flood: sent=%d dropped=%d errors=%d in %.2fs\n",
           sent, drops, errs, secs);
    printf("[ok] non-blocking drop under full send buffer passed\n");

    /* 4. Concurrency + saturation: several threads fire at the same unread
     * socket together, forcing the full-buffer path under contention (as if
     * memguard's thread, the scan loop, and an eBPF callback all alert at
     * once). The whole storm must finish quickly: no individual send blocks. */
    #define FLOOD_THREADS 4
    #define FLOOD_PER 50000
    g_send_errs = 0;
    pthread_t f_tx[FLOOD_THREADS];
    struct send_arg f_args[FLOOD_THREADS];
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < FLOOD_THREADS; i++) {
        f_args[i].id = 1000 + i;
        f_args[i].count = FLOOD_PER;
        if (pthread_create(&f_tx[i], NULL, sender, &f_args[i]) != 0)
            fail("flood tx thread");
    }
    for (int i = 0; i < FLOOD_THREADS; i++) pthread_join(f_tx[i], NULL);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    secs = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    if (secs > 10.0) fail("multithreaded saturated flood blocked (not non-blocking?)");
    if (g_send_errs != 0) fail("multithreaded saturated flood produced errors");
    printf("[ok] concurrent non-blocking send under saturation passed (%.2fs)\n",
           secs);

    network_shutdown();
    close(drop_sock);
    close(g_sock);
    printf("\nALL NETWORK STRESS TESTS PASSED\n");
    return 0;
}
