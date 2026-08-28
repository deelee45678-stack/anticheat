#define _GNU_SOURCE

#include "api.h"

#include "debugger.h"
#include "ebpf_monitor.h"
#include "envguard.h"
#include "integrity.h"
#include "memguard.h"
#include "network.h"
#include "report.h"
#include "scanner.h"
#include "telemetry.h"

#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>

/*
 * Single shared runtime state. The library is intentionally single-instance:
 * initialize_security_runtime() is idempotent and the game engine drives it
 * through the small C-linkage API below.
 */
static reporter_t     g_rep;
static memguard_t     g_mg;
static ebpf_monitor_t g_mon;
static atomic_int     g_initialized = 0;
static atomic_int     g_monitoring  = 0;
static atomic_int     g_kernel      = 0;
static pthread_t      g_mon_thread;

/* Background thread body for the eBPF monitor's blocking poll loop. */
static void *ebpf_run_thread(void *arg) {
    ebpf_monitor_run((ebpf_monitor_t *)arg, 0);
    return NULL;
}

int security_runtime_set_network_target(const char *server_ip, int port) {
    return initialize_network_client(server_ip, port);
}

int initialize_security_runtime(int flags) {
    if (atomic_load(&g_initialized)) {
        return 0; /* already running; idempotent */
    }

    if (flags & SEC_RUNTIME_NETWORK_LOGGING) {
        /* The actual broadcasts happen automatically from report_add() once the
         * UDP client is initialized; warn if no target was configured. */
        if (!network_is_active()) {
            report_add(&g_rep, SEV_INFO, "network",
                       "network logging requested but no UDP target configured "
                       "(call security_runtime_set_network_target)", NULL);
        }
    }

    report_init(&g_rep, NULL);
    report_set_quiet((flags & SEC_RUNTIME_QUIET) ? 1 : 0);

    if (flags & SEC_RUNTIME_SCAN) {
        scan_environment(&g_rep);
        scan_processes(&g_rep);

        if (is_debugged()) {
            report_add(&g_rep, SEV_CRITICAL, "debugger",
                       "this process is being traced or debugged", NULL);
        } else {
            report_add(&g_rep, SEV_INFO, "debugger",
                       "no debugger attached to this process", NULL);
        }

        int env = envguard_scan(&g_rep);
        if (env & ENVGUARD_VM) {
            if (is_debugged()) {
                report_add(&g_rep, SEV_HIGH, "envguard",
                           "virtualized environment confirmed with an attached "
                           "debugger (reverse-engineering sandbox)", NULL);
            } else {
                report_add(&g_rep, SEV_MEDIUM, "envguard",
                           "virtualized environment confirmed "
                           "(legitimate use: cloud gaming, CI, dev)", NULL);
            }
        }
        if (env & ENVGUARD_CONTAINER) {
            report_add(&g_rep, SEV_INFO, "envguard",
                       "containerized environment detected", NULL);
        }
    }

    if (flags & SEC_RUNTIME_TELEMETRY) {
        telemetry_run_simulation(&g_rep);
    }

    /* Live code-segment integrity monitor (background thread). */
    if (memguard_init(&g_mg, 250, &g_rep) == 0) {
        if (flags & SEC_RUNTIME_BACKGROUND) {
            if (memguard_start(&g_mg) == 0) {
                atomic_store(&g_monitoring, 1);
                report_add(&g_rep, SEV_INFO, "memguard",
                           "memory integrity monitor running", NULL);
            }
        } else {
            int n = memguard_check_once(&g_mg, &g_rep);
            report_add(&g_rep, SEV_INFO, "memguard",
                       n == 0 ? "own code segment memory integrity verified"
                              : "own code segment memory integrity violation",
                       NULL);
        }
    }

    /* Privileged kernel-level monitor (graceful fallback if unavailable).
     * Runs its ring-buffer poll loop in a detached background thread so the
     * game loop is never blocked. */
    if (flags & SEC_RUNTIME_KERNEL_MONITOR) {
        if (ebpf_monitor_init(&g_mon, &g_rep) == 0) {
            if (pthread_create(&g_mon_thread, NULL,
                               ebpf_run_thread, &g_mon) != 0) {
                ebpf_monitor_cleanup(&g_mon);
            } else {
                atomic_store(&g_kernel, 1);
                report_add(&g_rep, SEV_INFO, "ebpf",
                           "kernel monitor running", NULL);
            }
        }
    }

    atomic_store(&g_initialized, 1);
    return 0;
}

void shutdown_security_runtime(void) {
    if (!atomic_load(&g_initialized)) {
        return;
    }

    if (atomic_load(&g_monitoring)) {
        memguard_stop(&g_mg);
        atomic_store(&g_monitoring, 0);
        report_add(&g_rep, SEV_INFO, "memguard",
                   "memory integrity monitor stopped", NULL);
    }

    /* Stop the eBPF monitor thread (if running) and release kernel resources. */
    if (atomic_load(&g_kernel)) {
        ebpf_monitor_request_stop(&g_mon);
        pthread_join(g_mon_thread, NULL);
        ebpf_monitor_cleanup(&g_mon);
        atomic_store(&g_kernel, 0);
        report_add(&g_rep, SEV_INFO, "ebpf",
                   "kernel monitor stopped", NULL);
    }

    /* Tear down the UDP reporting client. */
    if (network_is_active()) {
        network_shutdown();
        report_add(&g_rep, SEV_INFO, "network",
                   "network reporting stopped", NULL);
    }

    atomic_store(&g_initialized, 0);
}

int security_runtime_verdict(void) {
    return report_verdict(&g_rep);
}

void security_runtime_counts(int out_counts[5]) {
    for (int i = 0; i < 5; i++) {
        out_counts[i] = 0;
    }
    for (size_t i = 0; i < g_rep.count; i++) {
        if (g_rep.findings[i].severity <= SEV_CRITICAL) {
            out_counts[g_rep.findings[i].severity]++;
        }
    }
}
