#define _GNU_SOURCE

#include "report.h"
#include "network.h"

#include <stdio.h>
#include <time.h>

static int g_quiet = 0;

static const char *severity_name(severity_t s) {
    switch (s) {
        case SEV_INFO:     return "INFO";
        case SEV_LOW:      return "LOW";
        case SEV_MEDIUM:   return "MEDIUM";
        case SEV_HIGH:     return "HIGH";
        case SEV_CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

void report_set_quiet(int quiet) {
    g_quiet = quiet;
}

void report_init(reporter_t *rep, const char *log_path) {
    rep->count = 0;
    rep->log_path = log_path;
}

void report_add(reporter_t *rep, severity_t sev, const char *module,
                const char *message, const char *detail) {
    if (rep->count >= MAX_FINDINGS) {
        return;
    }

    finding_t *f = &rep->findings[rep->count++];
    f->severity = sev;
    f->module = module;
    f->message = message;
    if (detail) {
        snprintf(f->detail, sizeof(f->detail), "%s", detail);
    } else {
        f->detail[0] = '\0';
    }

    if (!g_quiet) {
        printf("[%s] %s: %s", severity_name(sev), module, message);
        if (f->detail[0]) {
            printf(" (%s)", f->detail);
        }
        printf("\n");
    }

    /* Network reporting: broadcast MEDIUM-or-higher findings over UDP. The
     * send is non-blocking and a no-op when the client is uninitialized. */
    if (sev >= SEV_MEDIUM) {
        network_send_alert((int)sev, module, f->detail[0] ? f->detail : message);
    }

    if (rep->log_path) {
        FILE *log = fopen(rep->log_path, "a");
        if (log) {
            time_t now = time(NULL);
            struct tm tm;
            localtime_r(&now, &tm);
            fprintf(log, "%04d-%02d-%02d %02d:%02d:%02d [%s] %s: %s",
                    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                    tm.tm_hour, tm.tm_min, tm.tm_sec,
                    severity_name(sev), module, message);
            if (f->detail[0]) {
                fprintf(log, " (%s)", f->detail);
            }
            fprintf(log, "\n");
            fclose(log);
        }
    }
}

void report_summary(const reporter_t *rep) {
    int counts[5] = {0, 0, 0, 0, 0};
    for (size_t i = 0; i < rep->count; i++) {
        if (rep->findings[i].severity <= SEV_CRITICAL) {
            counts[rep->findings[i].severity]++;
        }
    }

    if (!g_quiet) {
        printf("\n--- Scan summary ---\n");
        printf("  INFO: %d | LOW: %d | MEDIUM: %d | HIGH: %d | CRITICAL: %d\n",
               counts[SEV_INFO], counts[SEV_LOW], counts[SEV_MEDIUM],
               counts[SEV_HIGH], counts[SEV_CRITICAL]);
    }
}

int report_verdict(const reporter_t *rep) {
    for (size_t i = 0; i < rep->count; i++) {
        if (rep->findings[i].severity >= SEV_MEDIUM) {
            return 1;
        }
    }
    return 0;
}
