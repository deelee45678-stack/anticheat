#ifndef ENVGUARD_H
#define ENVGUARD_H

#include "report.h"

/* Result flags returned by envguard_scan(). */
#define ENVGUARD_VM        0x1
#define ENVGUARD_CONTAINER 0x2

/*
 * Scan for virtualization and sandbox indicators.
 *
 * - CPUID hypervisor-present bit + hypervisor signature (VMware, Hyper-V,
 *   KVM, Xen, ...)
 * - DMI/BIOS strings under /sys/class/dmi/id/
 * - /proc/cpuinfo "hypervisor" flag and model-name markers
 * - container/sandbox indicators (/.dockerenv, /run/.containerenv, cgroup)
 *
 * Individual artifact hits are reported as INFO. The caller is expected to
 * classify the overall result (see main.c) so that a confirmed VM is MEDIUM
 * by default and escalates to HIGH when a debugger is attached.
 *
 * Returns a bitmask of ENVGUARD_VM / ENVGUARD_CONTAINER.
 */
int envguard_scan(reporter_t *rep);

#endif