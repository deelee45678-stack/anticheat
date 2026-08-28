#ifndef REPORT_H
#define REPORT_H

#include <stddef.h>

#define MAX_FINDINGS 256

typedef enum {
    SEV_INFO = 0,
    SEV_LOW,
    SEV_MEDIUM,
    SEV_HIGH,
    SEV_CRITICAL
} severity_t;

typedef struct {
    severity_t severity;
    const char *module;
    const char *message;
    char detail[256];
} finding_t;

typedef struct {
    finding_t findings[MAX_FINDINGS];
    size_t count;
    const char *log_path;
} reporter_t;

void report_init(reporter_t *rep, const char *log_path);
void report_set_quiet(int quiet);
void report_add(reporter_t *rep, severity_t sev, const char *module,
                const char *message, const char *detail);
void report_summary(const reporter_t *rep);
int report_verdict(const reporter_t *rep);

#endif
