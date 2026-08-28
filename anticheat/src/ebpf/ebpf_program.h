#ifndef EBPF_PROGRAM_H
#define EBPF_PROGRAM_H

#include <stddef.h>
#include <stdint.h>
#include <linux/bpf.h>

/* Syscall numbers (x86_64). The eBPF program compares the tracepoint's
 * "id" field against these to tag the recorded event. */
#define SYSCALL_CODE_PTRACE       101
#define SYSCALL_CODE_PV_READV     310
#define SYSCALL_CODE_PV_WRITEV    311

/* Ring-buffer event layout (packed, 32 bytes). */
#define EBPF_EVENT_SIZE 32

/* Upper bound on the number of instructions the program may contain. */
#define EBPF_MAX_INSNS 40

typedef struct __attribute__((packed)) {
    uint32_t code;       /* SYSCALL_CODE_* */
    uint32_t pad;
    uint64_t target_pid; /* ptrace: pid,  process_vm_*: pid */
    uint64_t caller_pid; /* tgid of the calling process */
    uint64_t request;    /* ptrace: request, process_vm_*: iov_len */
} ebpf_event_t;

/* Build the hand-assembled eBPF tracepoint program into `out`.
 * Returns 0 on success, -1 on failure.
 *
 * The single program is attached to all three syscall-entry tracepoints
 * (sys_enter_ptrace, sys_enter_process_vm_readv, sys_enter_process_vm_writev);
 * it tags each event with the syscall number so the monitor can tell them
 * apart. The ring-buffer map FD is patched into the LD_DW_IMM (pseudo-map-fd)
 * instruction at index EBPF_MAP_REF_INSNSN at load time, so the kernel
 * validates the map reference when the program is loaded.
 *
 * Without libbpf (HAVE_LIBBPF undefined at build time) this always returns -1
 * so the monitor knows it cannot load a kernel program and falls back to the
 * user-mode protections. */
int ebpf_program_build(struct bpf_insn *out, size_t max_insns,
                       size_t *insn_count);

/* Index of the LD_DW_IMM map-reference instruction (the one carrying the
 * ring-buffer map FD as its imm value). */
#define EBPF_MAP_REF_INSNSN 1

/* Human-readable name for a syscall code. */
const char *ebpf_syscall_name(uint32_t code);

#endif
