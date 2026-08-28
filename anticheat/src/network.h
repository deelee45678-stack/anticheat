#ifndef NETWORK_H
#define NETWORK_H

#include <stddef.h>

/*
 * Lightweight UDP network reporting engine.
 *
 * The client opens a single non-blocking UDP socket and broadcasts compact
 * JSON alert payloads to a configured server address. All sends are
 * non-blocking (O_NONBLOCK + MSG_DONTWAIT) and serialized through a short-lived
 * mutex, so calling network_send_alert() from a scanning loop, a background
 * thread, or a foreign game frame can never block on network lag.
 *
 * If the client was never initialized (or has been shut down) every function
 * degrades to a no-op, so the rest of the scanner can call it unconditionally.
 */

/* Initialize the non-blocking UDP client for `server_ip`:`port`.
 * Returns 0 on success, -1 on failure. Safe to call more than once. */
int initialize_network_client(const char *server_ip, int port);

/* Transmit an alert payload for a finding.
 * `severity` is the numeric severity (0=INFO .. 4=CRITICAL).
 * Returns the number of bytes sent, 0 if dropped/uninitialized, or -1 on error.
 * Never blocks. */
int network_send_alert(int severity, const char *module, const char *message);

/* Close the socket and disable network reporting. Safe to call at any time. */
void network_shutdown(void);

/* Returns 1 if the UDP client is initialized and active, 0 otherwise. */
int network_is_active(void);

#endif
