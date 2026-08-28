#define _GNU_SOURCE

#include "integrity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"

static void to_hex(const unsigned char *d, size_t n, char *out) {
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2] = hexd[d[i] >> 4];
        out[i * 2 + 1] = hexd[d[i] & 0x0f];
    }
    out[n * 2] = '\0';
}

static int hash_file(const char *path, unsigned char digest[SHA256_DIGEST_LEN]) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return -1;
    }

    sha256_ctx ctx;
    sha256_init(&ctx);
    unsigned char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        sha256_update(&ctx, buf, n);
    }
    if (ferror(f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    sha256_final(&ctx, digest);
    return 0;
}

int integrity_build_manifest(reporter_t *rep, const char *manifest_path,
                             const char **paths) {
    FILE *mf = fopen(manifest_path, "w");
    if (!mf) {
        report_add(rep, SEV_HIGH, "integrity",
                   "cannot create manifest file", manifest_path);
        return 1;
    }

    int failed = 0;
    for (size_t i = 0; paths[i]; i++) {
        unsigned char digest[SHA256_DIGEST_LEN];
        char hex[2 * SHA256_DIGEST_LEN + 1];
        if (hash_file(paths[i], digest) != 0) {
            char detail[320];
            snprintf(detail, sizeof(detail), "unreadable file: %s", paths[i]);
            report_add(rep, SEV_HIGH, "integrity", "cannot hash file", detail);
            failed = 1;
            continue;
        }
        to_hex(digest, SHA256_DIGEST_LEN, hex);
        fprintf(mf, "%s  %s\n", hex, paths[i]);
        report_add(rep, SEV_INFO, "integrity", "baseline recorded", paths[i]);
    }

    fclose(mf);
    return failed;
}

int integrity_verify_manifest(reporter_t *rep, const char *manifest_path) {
    FILE *mf = fopen(manifest_path, "r");
    if (!mf) {
        report_add(rep, SEV_HIGH, "integrity",
                   "cannot open manifest file", manifest_path);
        return 1;
    }

    char line[4096];
    int tampered = 0;
    while (fgets(line, sizeof(line), mf)) {
        size_t len = strlen(line);
        while (len && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        if (len < 2 * SHA256_DIGEST_LEN + 3 || line[2 * SHA256_DIGEST_LEN] != ' ') {
            continue;
        }

        line[2 * SHA256_DIGEST_LEN] = '\0';
        const char *path = line + 2 * SHA256_DIGEST_LEN + 2;

        unsigned char digest[SHA256_DIGEST_LEN];
        char hex[2 * SHA256_DIGEST_LEN + 1];
        if (hash_file(path, digest) != 0) {
            char detail[320];
            snprintf(detail, sizeof(detail),
                     "file missing or unreadable: %.250s", path);
            report_add(rep, SEV_HIGH, "integrity", "integrity check failed", detail);
            tampered = 1;
            continue;
        }

        to_hex(digest, SHA256_DIGEST_LEN, hex);
        if (strcmp(line, hex) != 0) {
            char detail[320];
            snprintf(detail, sizeof(detail), "hash mismatch: %.250s", path);
            report_add(rep, SEV_HIGH, "integrity",
                       "file content differs from baseline", detail);
            tampered = 1;
        }
    }
    fclose(mf);

    if (!tampered) {
        report_add(rep, SEV_INFO, "integrity",
                   "all files match baseline manifest", NULL);
    }
    return tampered;
}
