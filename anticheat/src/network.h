#ifndef NETWORK_H
#define NETWORK_H

#include <stddef.h>

/*
 * Lightweight, authenticated UDP network reporting engine.
 *
 * The client opens a single non-blocking UDP socket and broadcasts compact
 * JSON alert payloads to a configured server address. Every datagram carries
 * an HMAC-SHA256 signature ("sig") computed over a canonical representation of
 * the payload fields using a shared secret. The dashboard must verify the
 * signature before trusting or rendering an alert; datagrams with a missing or
 * invalid signature are rejected.
 *
 * All sends are non-blocking (O_NONBLOCK + MSG_DONTWAIT) and serialized through
 * a short-lived mutex, so calling network_send_alert() from a scanning loop, a
 * background thread, or a foreign game frame can never block on network lag. If
 * the kernel send buffer is full the datagram is dropped silently (returns 0),
 * never blocking or crashing.
 *
 * A per-(module,message) rate limiter caps identical alerts to a small window so
 * a burst of findings cannot flood the dashboard or spike egress.
 *
 * If the client was never initialized (or has been shut down) every function
 * degrades to a no-op, so the rest of the scanner can call it unconditionally.
 *
 * NOTE: the shared secret MUST be provisioned out-of-band (parameter or the
 * ANTICHEAT_NETWORK_KEY environment variable). This provides authentication and
 * integrity, not key management for large fleets.
 */

/* Initialize the non-blocking UDP client for `server_ip`:`port` using `key`
 * (or, if `key` is NULL, the ANTICHEAT_NETWORK_KEY environment variable) as the
 * HMAC secret. Resolves IPv4 and IPv6 via getaddrinfo(AF_UNSPEC).
 *
 * Returns 0 on success, -1 on failure (invalid address, port, or missing key).
 * A missing key is a hard failure: unauthenticated reporting is not allowed.
 * Safe to call more than once. */
int initialize_network_client(const char *server_ip, int port, const char *key);

/* Transmit an alert payload for a finding.
 * `severity` is the numeric severity (0=INFO .. 4=CRITICAL).
 * Returns the number of bytes sent, 0 if dropped/uninitialized (or rate-limited
 * / send-buffer full), or -1 on a non-recoverable error. Never blocks. */
int network_send_alert(int severity, const char *module, const char *message);

/* Close the socket and disable network reporting. Safe to call at any time. */
void network_shutdown(void);

/* Returns 1 if the UDP client is initialized and active, 0 otherwise. */
int network_is_active(void);

#endif
