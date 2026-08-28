#define _GNU_SOURCE
#include "envguard.h"
#include "report.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures = 0;

static int scan(void) {
    reporter_t rep;
    report_init(&rep, NULL);
    report_set_quiet(1);
    return envguard_scan(&rep);
}

static void write_file(const char *path, const char *content) {
    FILE *f = fopen(path, "w");
    if (!f) {
        perror("fopen");
        exit(2);
    }
    fputs(content, f);
    fclose(f);
}

/* Drive only the CPUID signature path; DMI dir is empty so it can't match. */
static void test_sig(const char *label, const char *sig, int expect_vm) {
    char tmpl[] = "/tmp/anticheat_dmi_XXXXXX";
    char *d = mkdtemp(tmpl);
    if (!d) {
        perror("mkdtemp");
        exit(2);
    }
    setenv("ANTICHEAT_TEST_HV_SIG", sig, 1);
    setenv("ANTICHEAT_TEST_DMI_DIR", d, 1);

    int r = scan();
    int vm = (r & ENVGUARD_VM) != 0;

    if (vm != expect_vm) {
        fprintf(stderr, "FAIL %s (sig=%s): expected VM=%d, got %d\n",
                label, sig, expect_vm, vm);
        failures++;
    } else {
        printf("ok   %s (sig=%s -> VM=%d)\n", label, sig, vm);
    }

    unsetenv("ANTICHEAT_TEST_HV_SIG");
    unsetenv("ANTICHEAT_TEST_DMI_DIR");
    rmdir(d);
}

/* Drive only the DMI marker path; CPUID is pinned to a non-matching sig. */
static void test_dmi(const char *label, const char *content, int expect_vm) {
    char tmpl[] = "/tmp/anticheat_dmi_XXXXXX";
    char *d = mkdtemp(tmpl);
    if (!d) {
        perror("mkdtemp");
        exit(2);
    }
    char path[1024];
    snprintf(path, sizeof(path), "%s/product_name", d);
    write_file(path, content);

    setenv("ANTICHEAT_TEST_HV_SIG", "PhysicalPhysi", 1);
    setenv("ANTICHEAT_TEST_DMI_DIR", d, 1);

    int r = scan();
    int vm = (r & ENVGUARD_VM) != 0;

    if (vm != expect_vm) {
        fprintf(stderr, "FAIL %s (dmi=%s): expected VM=%d, got %d\n",
                label, content, expect_vm, vm);
        failures++;
    } else {
        printf("ok   %s (dmi=\"%s\" -> VM=%d)\n", label, content, vm);
    }

    unsetenv("ANTICHEAT_TEST_HV_SIG");
    unsetenv("ANTICHEAT_TEST_DMI_DIR");
    remove(path);
    rmdir(d);
}

int main(void) {
    printf("== envguard: CPUID hypervisor signatures ==\n");
    test_sig("VMware",    "VMwareVMware", 1);
    test_sig("Hyper-V",   "Microsoft Hv", 1);
    test_sig("KVM",       "KVMKVMKVM",    1);
    test_sig("Xen",       "XenVMMXenVMM", 1);
    test_sig("Parallels", "prl hypervsr", 1);
    test_sig("VirtualBox","VrtualPCvV",   1);
    test_sig("bhyve",     "bhyve bhyve",  1);
    test_sig("physical (no match)", "PhysicalPhysi", 0);

    printf("== envguard: DMI/BIOS virtualization markers ==\n");
    test_dmi("QEMU marker",   "QEMU Virtual Machine",   1);
    test_dmi("Bochs marker",  "Bochs",                  1);
    test_dmi("VirtualBox",    "innotek VirtualBox",     1);
    test_dmi("physical OEM",  "Dell Inc.",              0);
    test_dmi("empty DMI dir", "",                       0);

    printf("== envguard: real host scan (no overrides) ==\n");
    unsetenv("ANTICHEAT_TEST_HV_SIG");
    unsetenv("ANTICHEAT_TEST_DMI_DIR");
    int r = scan();
    if ((r & ~(ENVGUARD_VM | ENVGUARD_CONTAINER)) != 0) {
        fprintf(stderr, "FAIL real scan returned invalid bits: %d\n", r);
        failures++;
    } else {
        printf("ok   real host scan returned valid bitmask (%d)\n", r);
    }

    if (failures) {
        fprintf(stderr, "\n%d test(s) failed\n", failures);
        return 1;
    }
    printf("\nall envguard tests passed\n");
    return 0;
}
