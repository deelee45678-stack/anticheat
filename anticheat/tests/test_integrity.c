#define _GNU_SOURCE
#include "integrity.h"
#include "report.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures = 0;

static void write_file(const char *path, const char *content) {
    FILE *f = fopen(path, "w");
    if (!f) {
        perror("fopen");
        exit(2);
    }
    fputs(content, f);
    fclose(f);
}

static int run_verify(const char *manifest) {
    reporter_t rep;
    report_init(&rep, NULL);
    report_set_quiet(1);
    return integrity_verify_manifest(&rep, manifest);
}

static void expect(const char *label, int actual, int expected) {
    if (actual != expected) {
        fprintf(stderr, "FAIL %s: expected %d, got %d\n",
                label, expected, actual);
        failures++;
    } else {
        printf("ok   %s\n", label);
    }
}

int main(void) {
    char tmpl[] = "/tmp/anticheat_integrity_XXXXXX";
    char *dir = mkdtemp(tmpl);
    if (!dir) {
        perror("mkdtemp");
        return 2;
    }

    char f1[1024], f2[1024], f3[1024], manifest[1024];
    snprintf(f1, sizeof(f1), "%s/a.bin", dir);
    snprintf(f2, sizeof(f2), "%s/b.bin", dir);
    snprintf(f3, sizeof(f3), "%s/c.bin", dir);
    snprintf(manifest, sizeof(manifest), "%s/manifest.sha256", dir);

    write_file(f1, "trusted payload one");
    write_file(f2, "trusted payload two");
    write_file(f3, "trusted payload three");

    const char *paths[] = {f1, f2, f3, NULL};

    reporter_t build_rep;
    report_init(&build_rep, NULL);
    report_set_quiet(1);
    if (integrity_build_manifest(&build_rep, manifest, paths) != 0) {
        fprintf(stderr, "FAIL build manifest\n");
        failures++;
    } else {
        printf("ok   build manifest\n");
    }

    /* All files match the manifest. */
    expect("verify clean (all match)", run_verify(manifest), 0);

    /* Tamper with one file. */
    write_file(f2, "TAMPERED payload two!!!");
    expect("verify detects tampered file", run_verify(manifest), 1);

    /* Restore and delete a baselined file. */
    write_file(f2, "trusted payload two");
    if (remove(f3) != 0) {
        perror("remove");
    }
    expect("verify detects missing file", run_verify(manifest), 1);

    /* Malformed manifest: only garbage lines -> nothing to verify. */
    write_file(manifest, "this is not a valid manifest line at all\n");
    expect("verify malformed-only manifest (clean no-crash)", run_verify(manifest), 0);

    /* Malformed manifest pointing at a nonexistent file -> clean failure. */
    char hex64[65];
    memset(hex64, 'f', 64);
    hex64[64] = '\0';
    char bad[1200];
    snprintf(bad, sizeof(bad),
             "%s /tmp/anticheat_integrity_missing_%.6d.bin\n", hex64, (int)getpid());
    write_file(manifest, bad);
    expect("verify missing referenced file (clean failure)", run_verify(manifest), 1);

    /* Cleanup. */
    remove(f1);
    remove(f2);
    remove(dir);
    rmdir(dir);

    if (failures) {
        fprintf(stderr, "\n%d test(s) failed\n", failures);
        return 1;
    }
    printf("\nall integrity tests passed\n");
    return 0;
}
