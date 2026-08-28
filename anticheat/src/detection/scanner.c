#define _GNU_SOURCE

#include "scanner.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Signatures of well-known game cheat and memory-editing tools. The scanner
 * matches a process name or command line against these (case-insensitive).
 */
static const char *const KNOWN_CHEAT_EXES[] = {
    "cheatengine", "cheatengine-x86_64", "ceserver", "artmoney",
    "gameconqueror", "scanmem", "tsearch", "cheat-o-matic", "cheatomatic",
    "memspy", "memscanner", "x64dbg", "x32dbg", "ollydbg", "ollyice",
    "windbg", "ida", "ida64", "ghidra", "ghidrarun", "radare2", "r2",
    "gdb", "lldb", "strace", "ltrace",
    NULL
};

static const char *const CHEAT_CMD_MARKERS[] = {
    "aimbot", "wallhack", "esp", "speedhack", "noclip", "injector",
    "trainer", "cheat", "hack",
    NULL
};

static const char *const SUSPICIOUS_DIRS[] = {
    "/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/",
    NULL
};

static int str_icase_cmp(const char *a, const char *b) {
    while (*a && *b) {
        int ca = tolower((unsigned char)*a);
        int cb = tolower((unsigned char)*b);
        if (ca != cb) {
            return ca - cb;
        }
        a++;
        b++;
    }
    return tolower((unsigned char)*a) - tolower((unsigned char)*b);
}

static int is_known_cheat_name(const char *name) {
    for (size_t i = 0; KNOWN_CHEAT_EXES[i]; i++) {
        if (str_icase_cmp(name, KNOWN_CHEAT_EXES[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static int contains_marker(const char *text) {
    char lower[1024];
    size_t len = strlen(text);
    if (len >= sizeof(lower)) {
        len = sizeof(lower) - 1;
    }
    for (size_t i = 0; i < len; i++) {
        lower[i] = (char)tolower((unsigned char)text[i]);
    }
    lower[len] = '\0';

    for (size_t i = 0; CHEAT_CMD_MARKERS[i]; i++) {
        const char *m = CHEAT_CMD_MARKERS[i];
        size_t mlen = strlen(m);
        char *hit = strstr(lower, m);
        while (hit) {
            char before = hit == lower ? '\0' : hit[-1];
            char after = hit[mlen];
            if ((before == '\0' || !isalnum((unsigned char)before)) &&
                (after == '\0' || !isalnum((unsigned char)after))) {
                return 1;
            }
            hit = strstr(hit + 1, m);
        }
    }
    return 0;
}

static ssize_t read_proc_file(const char *path, char *out, size_t n) {
    FILE *f = fopen(path, "r");
    if (!f) {
        return -1;
    }
    ssize_t got = (ssize_t)fread(out, 1, n - 1, f);
    out[got] = '\0';
    fclose(f);
    return got;
}

static long proc_status_long(const char *path, const char *field) {
    FILE *f = fopen(path, "r");
    if (!f) {
        return -1;
    }
    char line[256];
    long value = -1;
    size_t flen = strlen(field);
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, field, flen) == 0 && line[flen] == ':') {
            value = strtol(line + flen + 1, NULL, 10);
            break;
        }
    }
    fclose(f);
    return value;
}

static void inspect_process(reporter_t *rep, int pid) {
    char path[64];
    char name[256];
    char cmdline[1024];
    char exe[PATH_MAX];

    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    if (read_proc_file(path, name, sizeof(name)) < 0) {
        return;
    }
    size_t nl = strlen(name);
    while (nl && (name[nl - 1] == '\n' || name[nl - 1] == '\r')) {
        name[--nl] = '\0';
    }

    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    cmdline[0] = '\0';
    ssize_t nread = read_proc_file(path, cmdline, sizeof(cmdline));
    if (nread > 0) {
        for (ssize_t i = 0; i < nread; i++) {
            if (cmdline[i] == '\0') {
                cmdline[i] = ' ';
            }
        }
        size_t cl = strlen(cmdline);
        while (cl && cmdline[cl - 1] == ' ') {
            cmdline[--cl] = '\0';
        }
    }

    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    exe[0] = '\0';
    ssize_t el = readlink(path, exe, sizeof(exe) - 1);
    if (el >= 0) {
        exe[el] = '\0';
    }

    if (is_known_cheat_name(name)) {
        char detail[320];
        snprintf(detail, sizeof(detail), "pid=%d name=%s cmdline=%.200s",
                 pid, name, cmdline[0] ? cmdline : "(none)");
        report_add(rep, SEV_HIGH, "process",
                   "known cheat/debugger tool process found", detail);
        return;
    }

    if (cmdline[0] && contains_marker(cmdline)) {
        char detail[320];
        snprintf(detail, sizeof(detail), "pid=%d cmdline=%.240s", pid, cmdline);
        report_add(rep, SEV_MEDIUM, "process",
                   "suspicious cheat-related keyword in command line", detail);
    }

    if (exe[0]) {
        for (size_t i = 0; SUSPICIOUS_DIRS[i]; i++) {
            if (strncmp(exe, SUSPICIOUS_DIRS[i], strlen(SUSPICIOUS_DIRS[i])) == 0) {
                char detail[320];
                snprintf(detail, sizeof(detail), "pid=%d exe=%s", pid, exe);
                report_add(rep, SEV_MEDIUM, "process",
                           "executable running from a writable temp location", detail);
                break;
            }
        }
    }

    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    long tracer = proc_status_long(path, "TracerPid");
    if (tracer > 0) {
        char detail[320];
        snprintf(detail, sizeof(detail), "pid=%d is traced by pid=%ld", pid, tracer);
        report_add(rep, SEV_MEDIUM, "process",
                   "process has an attached tracer (possible live debugging)", detail);
    }
}

void scan_processes(reporter_t *rep) {
    DIR *dir = opendir("/proc");
    if (!dir) {
        report_add(rep, SEV_HIGH, "process", "cannot open /proc",
                   strerror(errno));
        return;
    }

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (!isdigit((unsigned char)ent->d_name[0])) {
            continue;
        }
        int pid = atoi(ent->d_name);
        if (pid == getpid() || pid == getppid()) {
            continue;
        }
        inspect_process(rep, pid);
    }
    closedir(dir);
}

void scan_environment(reporter_t *rep) {
    static const char *const INJECTION_VARS[] = {
        "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_DEBUG",
        "LD_HWCAP_MASK", "LD_PROFILE", "LD_ORIGIN_PATH", "MALLOC_TRACE",
        NULL
    };

    for (size_t i = 0; INJECTION_VARS[i]; i++) {
        const char *val = getenv(INJECTION_VARS[i]);
        if (val && val[0]) {
            char detail[512];
            snprintf(detail, sizeof(detail), "%s=%s", INJECTION_VARS[i], val);
            report_add(rep, SEV_HIGH, "environment",
                       "library injection vector is set", detail);
        }
    }

    const char *sandbox = getenv("SNAP");
    if (sandbox) {
        report_add(rep, SEV_INFO, "environment",
                   "process is running inside a sandbox/container",
                   sandbox);
    }
}
