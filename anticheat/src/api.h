#ifndef ANTICHEAT_API_H
#define ANTICHEAT_API_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Runtime control flags for initialize_security_runtime(). */
#define SEC_RUNTIME_SCAN           0x01  /* run one-shot process/env/debugger checks at init */
#define SEC_RUNTIME_BACKGROUND     0x02  /* start the background .text integrity monitor thread */
#define SEC_RUNTIME_KERNEL_MONITOR 0x04  /* attempt the privileged eBPF cross-process monitor */
#define SEC_RUNTIME_TELEMETRY      0x08  /* run the server-side telemetry simulation at init */
#define SEC_RUNTIME_QUIET          0x10  /* suppress console output (library default) */
#define SEC_RUNTIME_NETWORK_LOGGING 0x20 /* broadcast MEDIUM+ findings over UDP */

/*
 * Initialize the anti-cheat security runtime. Safe to call once from a foreign
 * game loop (Unreal/Unity) before or during initialization. It performs the
 * requested one-shot checks and starts any background threads, then returns
 * immediately.
 *
 * Returns 0 on success (runtime initialized), or -1 if it was already
 * initialized or could not start.
 */
int initialize_security_runtime(int flags);

/*
 * Configure the UDP alert destination. Must be called (typically before
 * initialize_security_runtime with SEC_RUNTIME_NETWORK_LOGGING) to enable
 * network reporting. Returns 0 on success, -1 on failure.
 */
int security_runtime_set_network_target(const char *server_ip, int port);

/*
 * Tear down the security runtime: stops background threads and releases
 * resources. Safe to call from the game's shutdown path.
 */
void shutdown_security_runtime(void);

/*
 * Query the current verdict of the security runtime.
 *
 * Returns 0 if no MEDIUM-or-higher findings have been recorded, or 1 if at
 * least one MEDIUM/HIGH/CRITICAL finding is present (the same semantics as the
 * standalone scanner's exit code).
 */
int security_runtime_verdict(void);

/*
 * Number of findings recorded since initialization, grouped by severity into
 * the caller-provided 5-element array indexed by severity_t
 * (INFO, LOW, MEDIUM, HIGH, CRITICAL).
 */
void security_runtime_counts(int out_counts[5]);

#ifdef __cplusplus
}
#endif

#endif
