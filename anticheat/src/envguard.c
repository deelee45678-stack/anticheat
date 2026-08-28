#define _GNU_SOURCE

#include "envguard.h"

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* CPUID via inline assembly (x86). */
static void cpuid(unsigned int leaf, unsigned int subleaf,
                  unsigned int *eax, unsigned int *ebx,
                  unsigned int *ecx, unsigned int *edx) {
    __asm__ volatile ("cpuid"
                      : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                      : "a"(leaf), "c"(subleaf));
}

static void check_cpuid(reporter_t *rep, int *vm_hits) {
    unsigned int eax, ebx, ecx, edx;

    cpuid(1, 0, &eax, &ebx, &ecx, &edx);
    if ((ecx & 0x80000000u) == 0) {
        report_add(rep, SEV_INFO, "envguard",
                   "CPUID: hypervisor-present bit not set", NULL);
        return;
    }

    cpuid(0x40000000u, 0, &eax, &ebx, &ecx, &edx);
    char sig[13];
    memcpy(sig + 0, &ebx, 4);
    memcpy(sig + 4, &ecx, 4);
    memcpy(sig + 8, &edx, 4);
    sig[12] = '\0';

    report_add(rep, SEV_INFO, "envguard",
               "CPUID: hypervisor present", sig);

    static const struct {
        const char *sig;
        const char *name;
    } known[] = {
        {"VMwareVMware", "VMware"},
        {"Microsoft Hv", "Microsoft Hyper-V"},
        {"KVMKVMKVM",    "KVM"},
        {"XenVMMXenVMM", "Xen"},
        {"prl hypervsr", "Parallels"},
        {"VrtualPCvV",   "VirtualBox"},
        {"bhyve bhyve",  "bhyve"},
        {NULL, NULL}
    };

    for (size_t i = 0; known[i].sig; i++) {
        if (strncmp(sig, known[i].sig, 12) == 0) {
            char detail[64];
            snprintf(detail, sizeof(detail), "signature=%s", known[i].name);
            report_add(rep, SEV_INFO, "envguard",
                       "hypervisor signature identified", detail);
            (*vm_hits)++;
            break;
        }
    }
}

static void check_dmi_file(reporter_t *rep, const char *path,
                           const char *label, int *vm_hits) {
    char buf[1024];
    FILE *f = fopen(path, "r");
    if (!f) {
        return;
    }
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return;
    }
    fclose(f);
    buf[strcspn(buf, "\n")] = '\0';
    if (buf[0] == '\0') {
        return;
    }

    static const char *const markers[] = {
        "virtualbox", "qemu", "vmware", "bochs", "innotek",
        "kvm", "xen", "virtual machine", "hvm", "parallels",
        NULL
    };

    char lower[1024];
    size_t len = strlen(buf);
    if (len >= sizeof(lower)) {
        len = sizeof(lower) - 1;
    }
    for (size_t i = 0; i < len; i++) {
        lower[i] = (char)tolower((unsigned char)buf[i]);
    }
    lower[len] = '\0';

    for (size_t i = 0; markers[i]; i++) {
        if (strstr(lower, markers[i])) {
            char detail[320];
            snprintf(detail, sizeof(detail), "%s: %.200s", label, buf);
            report_add(rep, SEV_INFO, "envguard",
                       "virtualization marker in DMI/BIOS data", detail);
            (*vm_hits)++;
            break;
        }
    }
}

static void check_dmi(reporter_t *rep, int *vm_hits) {
    static const struct {
        const char *path;
        const char *label;
    } files[] = {
        {"/sys/class/dmi/id/product_name", "product_name"},
        {"/sys/class/dmi/id/sys_vendor",   "sys_vendor"},
        {"/sys/class/dmi/id/board_vendor", "board_vendor"},
        {"/sys/class/dmi/id/bios_vendor",  "bios_vendor"}
    };

    int accessible = 0;
    for (size_t i = 0; i < 4; i++) {
        FILE *f = fopen(files[i].path, "r");
        if (f) {
            accessible = 1;
            fclose(f);
        }
    }

    if (!accessible) {
        report_add(rep, SEV_INFO, "envguard",
                   "DMI data not accessible (missing or requires root)",
                   NULL);
        return;
    }

    for (size_t i = 0; i < 4; i++) {
        check_dmi_file(rep, files[i].path, files[i].label, vm_hits);
    }
}

static void check_cpuinfo(reporter_t *rep, int *vm_hits) {
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f) {
        return;
    }

    char line[1024];
    char model[256] = {0};
    int hypervisor_flag = 0;
    int model_marker = 0;

    static const char *const markers[] = {
        "virtualbox", "qemu", "vmware", "bochs", "kvm", "xen", NULL
    };

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "flags", 5) == 0 && strstr(line, "hypervisor")) {
            hypervisor_flag = 1;
        }
        if (strncmp(line, "model name", 10) == 0) {
            const char *colon = strchr(line, ':');
            if (!colon) {
                continue;
            }
            char *v = (char *)colon + 1;
            while (*v == ' ' || *v == '\t') {
                v++;
            }
            v[strcspn(v, "\n")] = '\0';
            snprintf(model, sizeof(model), "%s", v);

            char lower[256];
            size_t len = strlen(v);
            if (len >= sizeof(lower)) {
                len = sizeof(lower) - 1;
            }
            for (size_t i = 0; i < len; i++) {
                lower[i] = (char)tolower((unsigned char)v[i]);
            }
            lower[len] = '\0';

            for (size_t i = 0; markers[i]; i++) {
                if (strstr(lower, markers[i])) {
                    model_marker = 1;
                    break;
                }
            }
        }
    }
    fclose(f);

    if (hypervisor_flag) {
        report_add(rep, SEV_INFO, "envguard",
                   "'hypervisor' flag present in /proc/cpuinfo", NULL);
    }
    if (model_marker) {
        report_add(rep, SEV_INFO, "envguard",
                   "virtualization marker in CPU model name", model);
    }
    if (hypervisor_flag || model_marker) {
        (*vm_hits)++;
    }
}

static void check_container(reporter_t *rep, int *container_hits) {
    if (access("/.dockerenv", F_OK) == 0) {
        report_add(rep, SEV_INFO, "envguard",
                   "container indicator: /.dockerenv present", NULL);
        (*container_hits)++;
        return;
    }
    if (access("/run/.containerenv", F_OK) == 0) {
        report_add(rep, SEV_INFO, "envguard",
                   "container indicator: /run/.containerenv present", NULL);
        (*container_hits)++;
        return;
    }

    FILE *f = fopen("/proc/1/cgroup", "r");
    if (!f) {
        return;
    }

    char line[512];
    int hit = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "docker") || strstr(line, "kubepods") ||
            strstr(line, "containerd") || strstr(line, "lxc")) {
            hit = 1;
            break;
        }
    }
    fclose(f);

    if (hit) {
        report_add(rep, SEV_INFO, "envguard",
                   "container indicator: cgroup names a container runtime",
                   NULL);
        (*container_hits)++;
    }
}

int envguard_scan(reporter_t *rep) {
    int vm_hits = 0;
    int container_hits = 0;

    check_cpuid(rep, &vm_hits);
    check_dmi(rep, &vm_hits);
    check_cpuinfo(rep, &vm_hits);
    check_container(rep, &container_hits);

    return (vm_hits ? ENVGUARD_VM : 0) |
           (container_hits ? ENVGUARD_CONTAINER : 0);
}