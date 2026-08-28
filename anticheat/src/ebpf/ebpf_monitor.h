#ifndef EBPF_MONITOR_H
#define EBPF_MONITOR_H

#include "report.h"

#ifdef HAVE_LIBBPF
struct ring_buffer;
#endif

#include <signal.h>

/*
 * eBPF kernel-level monitor for unauthorized cross-process memory access.
 *
 * The monitor loads a tiny eBPF tracepoint program (built by ebpf_program.c)
 * and attaches it to the three syscall-entry tracepoints that can be abused to
 * read or write another process's memory:
 *   - sys_enter_ptrace
 *   - sys_enter_process_vm_readv
 *   - sys_enter_process_vm_writev
 *
 * Every such syscall from any process on the system is recorded into a ring
 * buffer and escalated to a CRITICAL kernel-level finding:
 *   "[CRITICAL] KERNEL: Unauthorized cross-process memory access blocked!"
 *
 * If the host lacks eBPF support, root privileges, or the libbpf headers were
 * unavailable at build time, the monitor disables itself gracefully with an
 * [INFO] log and the scanner relies entirely on its user-mode protections
 * (debugger detection, process scan, envguard, etc.).
 */

typedef struct ebpf_monitor ebpf_monitor_t;

/*
 * Opaque monitor state. All kernel handles are non-negative fds (or NULL for
 * the ring buffer) so cleanup is always safe to call.
 */
struct ebpf_monitor {
    reporter_t *rep;
    int active;
    volatile sig_atomic_t stop;
    int map_fd;
    int prog_fd;
    int tp_fd[3];
#ifdef HAVE_LIBBPF
    struct ring_buffer *rb;
#else
    void *rb;
#endif
};

/* Initialize the kernel monitor.
 * Returns 0 if the kernel-level monitor is active, or -1 if it was disabled
 * (and an [INFO] fallback finding was recorded). */
int ebpf_monitor_init(ebpf_monitor_t *m, reporter_t *rep);

/* Run the monitor's ring-buffer poll loop for up to `duration_sec` seconds
 * (0 = run until a signal/quit). Only meaningful when init returned 0. */
int ebpf_monitor_run(ebpf_monitor_t *m, int duration_sec);

/* Request the run loop to stop (thread-safe). The next poll iteration returns. */
void ebpf_monitor_request_stop(ebpf_monitor_t *m);

/* Tear down all kernel resources loaded by ebpf_monitor_init. */
void ebpf_monitor_cleanup(ebpf_monitor_t *m);

#endif
