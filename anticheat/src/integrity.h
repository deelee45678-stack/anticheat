#ifndef INTEGRITY_H
#define INTEGRITY_H

#include "report.h"

int integrity_build_manifest(reporter_t *rep, const char *manifest_path,
                             const char **paths);
int integrity_verify_manifest(reporter_t *rep, const char *manifest_path);

#endif
