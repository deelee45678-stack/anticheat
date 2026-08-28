#define _GNU_SOURCE

#include "ebpf_program.h"

#include <stddef.h>

/*
 * Hand-assembled eBPF tracepoint program.
 *
 * This environment has no clang/BPF toolchain and no kernel BTF, so instead
 * of compiling a .c BPF source we emit the BPF instruction stream directly.
 * The program is attached (by the monitor) to three syscall-entry
 * tracepoints: sys_enter_ptrace, sys_enter_process_vm_readv and
 * sys_enter_process_vm_writev.
 *
 * For every such syscall it records a 32-byte event into a ring buffer:
 *   { u32 code; u32 pad; u64 target_pid; u64 caller_pid; u64 request; }
 *
 * The tracepoint context for sys_enter is the kernel's
 * struct trace_event_raw_sys_enter, laid out (x86_64, little-endian) as:
 *   off 0  : common fields (trace_entry, 8 bytes)
 *   off 8  : int   __syscall_nr  (the syscall number)   -> "code"
 *   off 16 : u64   args[0]       (ptrace: request,
 *                                 process_vm_*: pid)     -> "target_pid"
 *   off 24 : u64   args[1]       (ptrace: pid,
 *                                 process_vm_*: iov_len) -> "request"
 *
 * We therefore read:
 *   - the syscall number at ctx+8   -> "code"
 *   - args[0] at ctx+16            -> "target_pid"
 *   - args[1] at ctx+24            -> "request"
 *   - bpf_get_current_pid_tgid()>>32 -> "caller_pid"
 *
 * The ring-buffer map file descriptor is embedded into the LD_DW_IMM
 * instruction at load time (BPF_PSEUDO_MAP_FD), so the kernel validates the
 * map reference when the program is loaded.
 *
 * The instruction-building macros normally supplied by the kernel headers
 * (BPF_MOV64_REG, BPF_LD_MAP_FD, ...) are not present in this userspace
 * environment, so the opcodes are emitted explicitly via struct literals.
 */

/* Compile-time guard: the context field offsets below assume little-endian. */
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "ebpf_program.c requires a little-endian target"
#endif

#ifdef HAVE_LIBBPF

#include <linux/bpf.h>

/* eBPF instruction opcodes (class | op | source). */
#define OP_ALU64_MOV_REG  0xbf  /* dst = src */
#define OP_ALU64_MOV_IMM  0xb7  /* dst = imm */
#define OP_ALU64_RSH_IMM  0x77  /* dst >>= imm (unsigned) */
#define OP_LDX_W          0x61  /* dst = *(u32 *)(src + off) */
#define OP_LDX_DW         0x79  /* dst = *(u64 *)(src + off) */
#define OP_STX_W          0x63  /* *(u32 *)(dst + off) = src */
#define OP_STX_DW         0x7b  /* *(u64 *)(dst + off) = src */
#define OP_JMP_JEQ_IMM    0x15  /* if (dst == imm) goto +off */
#define OP_JMP_CALL       0x85  /* call helper #imm */
#define OP_JMP_EXIT       0x95  /* return */
#define OP_LD_DW_MAP      0x18  /* dst = (u64)map_fd (pseudo, 2 insns) */

/* BPF helper function ids. */
#define HELPER_RINGBUF_RESERVE      131
#define HELPER_RINGBUF_SUBMIT       132
#define HELPER_GET_CURRENT_PID_TGID 14

/*
 * Build the instruction stream into `out` (indices shown in comments):
 *   0  : r6 = ctx
 *   1  : r1 = ringbuf_map_fd   (patched at load time)
 *   2  : (high dword of the map fd, must stay 0)
 *   3  : r2 = EBPF_EVENT_SIZE
 *   4  : r3 = 0
 *   5  : r0 = bpf_ringbuf_reserve(ringbuf, size, 0)
 *   6  : if (r0 == 0) goto 21 (exit)
 *   7  : r7 = r0
 *   8  : r1 = *(u32 *)(r6 + 8)        ; syscall number
 *   9  : *(u32 *)(r7 + 0) = r1        ; event.code
 *  10  : r1 = *(u64 *)(r6 + 16)       ; args[0]
 *  11  : *(u64 *)(r7 + 8) = r1        ; event.target_pid
 *  12  : r1 = bpf_get_current_pid_tgid()
 *  13  : r1 >>= 32                    ; tgid
 *  14  : *(u64 *)(r7 + 16) = r1       ; event.caller_pid
 *  15  : r1 = *(u64 *)(r6 + 24)       ; args[1]
 *  16  : *(u64 *)(r7 + 24) = r1       ; event.request
 *  17  : r1 = r7
 *  18  : r2 = 0
 *  19  : bpf_ringbuf_submit(event, 0)
 *  20  : r0 = 0
 *  21  : exit
 */
static const struct bpf_insn k_insns[] = {
    /* 0 */ { .code = OP_ALU64_MOV_REG, .dst_reg = BPF_REG_6, .src_reg = BPF_REG_1 },
    /* 1 */ { .code = OP_LD_DW_MAP, .dst_reg = BPF_REG_1, .src_reg = BPF_PSEUDO_MAP_FD, .imm = 0 },
    /* 2 */ { .code = 0, .dst_reg = BPF_REG_1, .imm = 0 },
    /* 3 */ { .code = OP_ALU64_MOV_IMM, .dst_reg = BPF_REG_2, .imm = EBPF_EVENT_SIZE },
    /* 4 */ { .code = OP_ALU64_MOV_IMM, .dst_reg = BPF_REG_3, .imm = 0 },
    /* 5 */ { .code = OP_JMP_CALL, .imm = HELPER_RINGBUF_RESERVE },
    /* 6 */ { .code = OP_JMP_JEQ_IMM, .dst_reg = BPF_REG_0, .off = 14 },
    /* 7 */ { .code = OP_ALU64_MOV_REG, .dst_reg = BPF_REG_7, .src_reg = BPF_REG_0 },
    /* 8 */ { .code = OP_LDX_W, .dst_reg = BPF_REG_1, .src_reg = BPF_REG_6, .off = 8 },
    /* 9 */ { .code = OP_STX_W, .dst_reg = BPF_REG_7, .src_reg = BPF_REG_1, .off = 0 },
    /* 10*/ { .code = OP_LDX_DW, .dst_reg = BPF_REG_1, .src_reg = BPF_REG_6, .off = 16 },
    /* 11*/ { .code = OP_STX_DW, .dst_reg = BPF_REG_7, .src_reg = BPF_REG_1, .off = 8 },
    /* 12*/ { .code = OP_JMP_CALL, .imm = HELPER_GET_CURRENT_PID_TGID },
    /* 13*/ { .code = OP_ALU64_RSH_IMM, .dst_reg = BPF_REG_1, .imm = 32 },
    /* 14*/ { .code = OP_STX_DW, .dst_reg = BPF_REG_7, .src_reg = BPF_REG_1, .off = 16 },
    /* 15*/ { .code = OP_LDX_DW, .dst_reg = BPF_REG_1, .src_reg = BPF_REG_6, .off = 24 },
    /* 16*/ { .code = OP_STX_DW, .dst_reg = BPF_REG_7, .src_reg = BPF_REG_1, .off = 24 },
    /* 17*/ { .code = OP_ALU64_MOV_REG, .dst_reg = BPF_REG_1, .src_reg = BPF_REG_7 },
    /* 18*/ { .code = OP_ALU64_MOV_IMM, .dst_reg = BPF_REG_2, .imm = 0 },
    /* 19*/ { .code = OP_JMP_CALL, .imm = HELPER_RINGBUF_SUBMIT },
    /* 20*/ { .code = OP_ALU64_MOV_IMM, .dst_reg = BPF_REG_0, .imm = 0 },
    /* 21*/ { .code = OP_JMP_EXIT },
};

#endif /* HAVE_LIBBPF */

int ebpf_program_build(struct bpf_insn *out, size_t max_insns,
                       size_t *insn_count) {
#ifdef HAVE_LIBBPF
    size_t n = sizeof(k_insns) / sizeof(k_insns[0]);
    if (!out || !insn_count || n > max_insns) {
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        out[i] = k_insns[i];
    }
    *insn_count = n;
    return 0;
#else
    (void)out;
    (void)max_insns;
    (void)insn_count;
    return -1;
#endif
}

const char *ebpf_syscall_name(uint32_t code) {
    switch (code) {
        case SYSCALL_CODE_PTRACE:    return "ptrace";
        case SYSCALL_CODE_PV_READV:  return "process_vm_readv";
        case SYSCALL_CODE_PV_WRITEV: return "process_vm_writev";
        default:                     return "unknown";
    }
}
