#define _GNU_SOURCE

#include "network.h"
#include "sha256.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* SHA-256 internal block size (RFC 4231). */
#define SHA256_BLOCK 64

/* Maximum serialized alert payload size (compact JSON line). Sized generously
 * so a realistic finding message is never truncated (truncation would desync
 * the HMAC canonical string from the transmitted field). */
#define NET_MAX_PAYLOAD 8192
/* Working buffers: payload + signature overhead. */
#define NET_BUF_EXTRA 512

/* Environment variable holding the shared HMAC secret when none is passed
 * explicitly to initialize_network_client(). */
#define NET_KEY_ENV "ANTICHEAT_NETWORK_KEY"

/* Per-(module,message) rate limiter: identical alerts are capped to one per
 * this window, so a burst of findings cannot flood the dashboard or spike
 * egress. */
#define NET_RATE_WINDOW_MS 1000
#define NET_RATE_SLOTS 64

/* Global non-blocking client state, guarded by g_lock for (re)configuration
 * and the actual send. The critical section is a single non-blocking sendto, so
 * callers are never exposed to network latency. */
static pthread_mutex_t      g_lock = PTHREAD_MUTEX_INITIALIZER;
static int                  g_sock = -1;
static struct sockaddr_storage g_addr;
static socklen_t            g_addrlen = 0;
static atomic_int           g_active = 0;

/* Shared HMAC secret (length kept separately; may be longer than the digest). */
static unsigned char        g_key[256];
static size_t               g_keylen = 0;

/* Approximate per-(module,message) rate limiter: a fixed slot cache keyed by a
 * 64-bit hash of "module\0message". Identical alerts within the window are
 * dropped. Collisions only cause an occasional legitimate alert to be rate
 * limited, which is acceptable for an alert stream. */
static uint64_t g_rate_hash[NET_RATE_SLOTS];
static long     g_rate_ts[NET_RATE_SLOTS];

static const char *severity_label(int severity) {
    switch (severity) {
        case 0:  return "INFO";
        case 1:  return "LOW";
        case 2:  return "MEDIUM";
        case 3:  return "HIGH";
        case 4:  return "CRITICAL";
        default: return "UNKNOWN";
    }
}

/* 64-bit FNV-1a hash over module + NUL + message, used as the rate-limit key. */
static uint64_t fnv1a(const char *a, const char *b) {
    uint64_t h = 1469598103934665603ULL;
    for (const char *p = a; p && *p; p++) {
        h ^= (unsigned char)*p;
        h *= 1099511628211ULL;
    }
    h ^= 0; /* separator */
    for (const char *p = b; p && *p; p++) {
        h ^= (unsigned char)*p;
        h *= 1099511628211ULL;
    }
    return h;
}

/* HMAC-SHA256(key, msg) -> out (32 bytes), built from the project's SHA-256. */
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

    unsigned char ipad[SHA256_BLOCK];
    unsigned char opad[SHA256_BLOCK];
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

/* Lowercase hex encode `n` bytes from `bin` into `out` (2n + 1 chars). */
static void to_hex(const unsigned char *bin, char *out, size_t n) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i]     = hex[(bin[i] >> 4) & 0xf];
        out[2 * i + 1] = hex[bin[i] & 0xf];
    }
    out[2 * n] = '\0';
}

/* Append `src` to `dst` with JSON string escaping (", \, and control chars). */
static void json_escape(char *dst, size_t dst_size, const char *src) {
    size_t i = 0;
    while (*src && i + 2 < dst_size) {
        unsigned char c = (unsigned char)*src++;
        if (c == '"' || c == '\\') {
            dst[i++] = '\\';
            dst[i++] = (char)c;
        } else if (c == '\n') {
            dst[i++] = '\\'; dst[i++] = 'n';
        } else if (c == '\t') {
            dst[i++] = '\\'; dst[i++] = 't';
        } else if (c < 0x20) {
            int n = snprintf(&dst[i], dst_size - i, "\\u%04x", c);
            if (n > 0) i += (size_t)n;
        } else {
            dst[i++] = (char)c;
        }
    }
    dst[i] = '\0';
}

int initialize_network_client(const char *server_ip, int port, const char *key) {
    if (!server_ip || port <= 0 || port > 65535) {
        return -1;
    }

    /* Resolve the shared secret: explicit parameter wins, otherwise the
     * environment. A missing key is a hard failure: unauthenticated reporting
     * is not allowed. */
    const char *k = key ? key : getenv(NET_KEY_ENV);
    if (!k || !*k) {
        return -1;
    }
    size_t klen = strlen(k);
    if (klen > sizeof(g_key)) {
        klen = sizeof(g_key);
    }

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;   /* IPv4 and IPv6 */
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);
    if (getaddrinfo(server_ip, portstr, &hints, &res) != 0 || !res) {
        return -1;
    }

    int sock = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock >= 0) {
            break;
        }
    }
    if (sock < 0) {
        freeaddrinfo(res);
        return -1;
    }

    /* Make the socket non-blocking so even a congested kernel buffer can never
     * stall the caller. */
    int fl = fcntl(sock, F_GETFL, 0);
    if (fl < 0 || fcntl(sock, F_SETFL, fl | O_NONBLOCK) < 0) {
        close(sock);
        freeaddrinfo(res);
        return -1;
    }

    pthread_mutex_lock(&g_lock);
    if (g_sock >= 0) {
        close(g_sock);
    }
    g_sock = sock;
    memcpy(&g_addr, res->ai_addr, res->ai_addrlen);
    g_addrlen = res->ai_addrlen;
    memcpy(g_key, k, klen);
    g_keylen = klen;
    memset(g_rate_ts, 0, sizeof(g_rate_ts));
    g_active = 1;
    pthread_mutex_unlock(&g_lock);

    freeaddrinfo(res);
    return 0;
}

int network_send_alert(int severity, const char *module, const char *message) {
    if (!module)  module  = "";
    if (!message) message = "";

    pthread_mutex_lock(&g_lock);
    if (!g_active || g_sock < 0) {
        pthread_mutex_unlock(&g_lock);
        return 0;
    }

    /* Per-(module,message) rate limiter. */
    long now_ms = (long)time(NULL) * 1000;
    uint64_t h = fnv1a(module, message);
    int slot = (int)(h % NET_RATE_SLOTS);
    if (g_rate_ts[slot] && g_rate_hash[slot] == h &&
        (now_ms - g_rate_ts[slot]) < NET_RATE_WINDOW_MS) {
        pthread_mutex_unlock(&g_lock);
        return 0; /* rate-limited: dropped silently */
    }
    g_rate_hash[slot] = h;
    g_rate_ts[slot] = now_ms;

    char mod_esc[256];
    char msg_esc[NET_MAX_PAYLOAD];
    json_escape(mod_esc, sizeof(mod_esc), module);
    json_escape(msg_esc, sizeof(msg_esc), message);

    long ts = (long)time(NULL);

    /* Compact JSON body (without the signature). */
    char body[NET_MAX_PAYLOAD + NET_BUF_EXTRA];
    snprintf(body, sizeof(body),
             "{\"severity\":%d,\"sev_label\":\"%s\","
             "\"module\":\"%s\",\"message\":\"%s\",\"ts\":%ld",
             severity, severity_label(severity),
             mod_esc, msg_esc, ts);

    /* Canonical message for HMAC: raw, unescaped fields joined by '|'.
     * Both client and dashboard reconstruct this identically from the parsed
     * fields, so JSON escaping never affects the signature. */
    char canon[NET_MAX_PAYLOAD + NET_BUF_EXTRA];
    int clen = snprintf(canon, sizeof(canon), "%d|%s|%s|%s|%ld",
                        severity, severity_label(severity),
                        module, message, ts);

    unsigned char dig[SHA256_DIGEST_LEN];
    hmac_sha256(g_key, g_keylen, (const unsigned char *)canon,
                (size_t)clen, dig);
    char sighex[SHA256_DIGEST_LEN * 2 + 1];
    to_hex(dig, sighex, SHA256_DIGEST_LEN);

    char buf[NET_MAX_PAYLOAD + NET_BUF_EXTRA];
    int len = snprintf(buf, sizeof(buf), "%s,\"sig\":\"%s\"}", body, sighex);

    ssize_t n = sendto(g_sock, buf, (size_t)len, MSG_DONTWAIT,
                       (struct sockaddr *)&g_addr, g_addrlen);

    pthread_mutex_unlock(&g_lock);

    if (n < 0) {
        /* EAGAIN/EWOULDBLOCK means the kernel send buffer was full: drop the
         * datagram rather than block. Other errors are reported to the caller. */
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }
    return (int)n;
}

void network_shutdown(void) {
    pthread_mutex_lock(&g_lock);
    if (g_sock >= 0) {
        close(g_sock);
        g_sock = -1;
    }
    g_active = 0;
    g_keylen = 0;
    pthread_mutex_unlock(&g_lock);
}

int network_is_active(void) {
    return atomic_load(&g_active) && g_sock >= 0;
}
