#define _GNU_SOURCE

#include "network.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* Maximum serialized alert payload size (compact JSON line). */
#define NET_MAX_PAYLOAD 1024

/* Global non-blocking client state, guarded by g_lock for (re)configuration
 * and the actual send. The critical section is a single non-blocking sendto, so
 * callers are never exposed to network latency. */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static int             g_sock = -1;
static struct sockaddr_in g_addr;
static atomic_int      g_active = 0;

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

int initialize_network_client(const char *server_ip, int port) {
    if (!server_ip || port <= 0 || port > 65535) {
        return -1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }

    /* Make the socket non-blocking so even a congested kernel buffer can never
     * stall the caller. */
    int fl = fcntl(sock, F_GETFL, 0);
    if (fl < 0 || fcntl(sock, F_SETFL, fl | O_NONBLOCK) < 0) {
        close(sock);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, server_ip, &addr.sin_addr) <= 0) {
        close(sock);
        return -1;
    }

    pthread_mutex_lock(&g_lock);
    if (g_sock >= 0) {
        close(g_sock);
    }
    g_sock = sock;
    g_addr = addr;
    g_active = 1;
    pthread_mutex_unlock(&g_lock);
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

    char mod_esc[256];
    char msg_esc[NET_MAX_PAYLOAD];
    json_escape(mod_esc, sizeof(mod_esc), module);
    json_escape(msg_esc, sizeof(msg_esc), message);

    char buf[NET_MAX_PAYLOAD];
    int len = snprintf(buf, sizeof(buf),
                       "{\"severity\":%d,\"sev_label\":\"%s\","
                       "\"module\":\"%s\",\"message\":\"%s\",\"ts\":%ld}",
                       severity, severity_label(severity),
                       mod_esc, msg_esc, (long)time(NULL));

    ssize_t n = sendto(g_sock, buf, (size_t)len, MSG_DONTWAIT,
                       (struct sockaddr *)&g_addr, sizeof(g_addr));

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
    pthread_mutex_unlock(&g_lock);
}

int network_is_active(void) {
    return atomic_load(&g_active) && g_sock >= 0;
}
