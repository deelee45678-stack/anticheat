#define _GNU_SOURCE

#include "debugger.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <unistd.h>

bool detect_tracer_pid(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) {
        return false;
    }

    char line[256];
    long tracer = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            tracer = strtol(line + 10, NULL, 10);
            break;
        }
    }
    fclose(f);

    return tracer > 0;
}

bool is_debugged(void) {
    if (detect_tracer_pid()) {
        return true;
    }

    /*
     * A process already being traced cannot PTRACE_TRACEME again; it gets
     * EPERM. A clean process can, and we immediately detach. A failed call
     * with EPERM while no tracer is reported is treated as debugger present
     * because that is exactly what an attached debugger looks like.
     */
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        return errno == EPERM;
    }
    ptrace(PTRACE_DETACH, getpid(), NULL, NULL);
    return false;
}
