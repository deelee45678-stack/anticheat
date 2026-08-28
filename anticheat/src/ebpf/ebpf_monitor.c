#define _GNU_SOURCE

#include "ebpf_monitor.h"
#include "ebpf_program.h"

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*
 * The three syscall-entry tracepoints we police.
 */
#ifdef HAVE_LIBBPF

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static const char *k_tracepoints[3] = {
    "sys_enter_ptrace",
    "sys_enter_process_vm_readv",
    "sys_enter_process_vm_writev",
};

/* Ring-buffer callback: a cross-process memory syscall was captured. */
static int ebpf_handle_event(void *ctx, void *data, size_t size) {
    ebpf_monitor_t *m = ctx;
    if (!m || size < sizeof(ebpf_event_t)) {
        return 0;
    }

    const ebpf_event_t *ev = data;
    char detail[256];
    snprintf(detail, sizeof(detail),
             "syscall=%s target_pid=%llu caller_pid=%llu",
             ebpf_syscall_name(ev->code),
             (unsigned long long)ev->target_pid,
             (unsigned long long)ev->caller_pid);

    report_add(m->rep, SEV_CRITICAL, "ebpf",
               "KERNEL: Unauthorized cross-process memory access blocked!",
               detail);
    return 0;
}

/* Disable the monitor with a single [INFO] fallback finding. */
static void ebpf_disable(ebpf_monitor_t *m, const char *reason) {
    char detail[128];
    snprintf(detail, sizeof(detail), "%s; falling back to user-mode protections",
             reason);
    report_add(m->rep, SEV_INFO, "ebpf",
               "kernel-level cross-process memory monitor disabled", detail);
    m->active = 0;
}

int ebpf_monitor_init(ebpf_monitor_t *m, reporter_t *rep) {
    if (!m || !rep) {
        return -1;
    }
    memset(m, 0, sizeof(*m));
    m->rep = rep;
    m->active = 0;
    m->stop = 0;
    m->map_fd = -1;
    m->prog_fd = -1;
    for (int i = 0; i < 3; i++) {
        m->tp_fd[i] = -1;
    }
    m->rb = NULL;

    /* The kernel monitor requires privileged (root) operation. */
    if (geteuid() != 0) {
        ebpf_disable(m, "not running as root");
        return -1;
    }

    /* Create the ring-buffer map that the BPF program writes into. */
    m->map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "ebpf_events", 0, 0,
                              64 * 4096, NULL);
    if (m->map_fd < 0) {
        ebpf_disable(m, "cannot create ring-buffer map (no eBPF support)");
        return -1;
    }

    /* Build and load the program, patching the map fd into the instruction. */
    struct bpf_insn insns[EBPF_MAX_INSNS];
    size_t n = 0;
    if (ebpf_program_build(insns, EBPF_MAX_INSNS, &n) != 0) {
        ebpf_disable(m, "cannot build eBPF program");
        return -1;
    }
    insns[EBPF_MAP_REF_INSNSN].imm = m->map_fd & 0xffffffff;
    insns[EBPF_MAP_REF_INSNSN + 1].imm = 0;

    m->prog_fd = bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT, "ebpf_xproc_guard",
                               "GPL", insns, n, NULL);
    if (m->prog_fd < 0) {
        ebpf_disable(m, "cannot load eBPF program (missing CAP_BPF?)");
        return -1;
    }

    /* Attach to each tracepoint. */
    for (int i = 0; i < 3; i++) {
        int tp = bpf_raw_tracepoint_open(k_tracepoints[i], m->prog_fd);
        if (tp < 0) {
            ebpf_disable(m, "cannot attach tracepoint (no tracepoint access?)");
            return -1;
        }
        m->tp_fd[i] = tp;
    }

    /* Wire up the ring buffer consumer. */
    m->rb = ring_buffer__new(m->map_fd, ebpf_handle_event, m, NULL);
    if (!m->rb) {
        ebpf_disable(m, "cannot create ring-buffer consumer");
        return -1;
    }

    m->active = 1;
    report_add(m->rep, SEV_INFO, "ebpf",
               "kernel-level cross-process memory monitor active "
               "(tracepoints: ptrace, process_vm_readv, process_vm_writev)",
               NULL);
    return 0;
}

int ebpf_monitor_run(ebpf_monitor_t *m, int duration_sec) {
    if (!m || !m->active || !m->rb) {
        return -1;
    }

    int elapsed = 0;
    while ((duration_sec == 0 || elapsed < duration_sec) && !m->stop) {
        int rc = ring_buffer__poll(m->rb, 250);
        if (rc < 0 && rc != -EINTR) {
            break;
        }
        elapsed++;
    }
    return 0;
}

void ebpf_monitor_request_stop(ebpf_monitor_t *m) {
    if (m) {
        m->stop = 1;
    }
}

void ebpf_monitor_cleanup(ebpf_monitor_t *m) {
    if (!m) {
        return;
    }
    if (m->rb) {
        ring_buffer__free(m->rb);
        m->rb = NULL;
    }
    for (int i = 0; i < 3; i++) {
        if (m->tp_fd[i] >= 0) {
            close(m->tp_fd[i]);
            m->tp_fd[i] = -1;
        }
    }
    if (m->prog_fd >= 0) {
        close(m->prog_fd);
        m->prog_fd = -1;
    }
    if (m->map_fd >= 0) {
        close(m->map_fd);
        m->map_fd = -1;
    }
    m->active = 0;
}

#else /* !HAVE_LIBBPF */

int ebpf_monitor_init(ebpf_monitor_t *m, reporter_t *rep) {
    if (!m || !rep) {
        return -1;
    }
    memset(m, 0, sizeof(*m));
    m->rep = rep;
    m->active = 0;
    report_add(rep, SEV_INFO, "ebpf",
               "kernel-level cross-process memory monitor disabled "
               "(libbpf not available at build time); "
               "falling back to user-mode protections",
               NULL);
    return -1;
}

void ebpf_monitor_request_stop(ebpf_monitor_t *m) {
    (void)m;
}

int ebpf_monitor_run(ebpf_monitor_t *m, int duration_sec) {
    (void)m;
    (void)duration_sec;
    return -1;
}

void ebpf_monitor_cleanup(ebpf_monitor_t *m) {
    (void)m;
}

#endif /* HAVE_LIBBPF */
