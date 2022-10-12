#include "quit.h"
#include <z_std.h>
#include <z_syscall.h>
#include <syscall.h>

#if __i386__ || __x86_64__
#include <asm/prctl.h>
#endif

#define PRIVATE_EXIT_SYSCALL SYS_sched_yield
#define PRIVATE_EXIT_MAGIC 0x6861636b

static context_t context = {};

void snapshot(context_t *p) {
    z_memcpy(&context, p, sizeof(context_t));
}

void quit(int status) {
    z_syscall(PRIVATE_EXIT_SYSCALL, 0, PRIVATE_EXIT_MAGIC, status);

#ifdef __x86_64__
    if (Z_RESULT_V(z_arch_prctl(ARCH_SET_FS, context.regs.fs_base)) < 0)
        z_exit_group(status);

    if (Z_RESULT_V(z_arch_prctl(ARCH_SET_GS, context.regs.gs_base)) < 0)
        z_exit_group(status);

    asm volatile(
        "mov %0, %%rdx;"
        "lea %c1(%%rdx), %%rcx;"
        "fldenv (%%rcx);"
        "ldmxcsr %c2(%%rdx);"
        "mov %c3(%%rdx), %%rsp;"
        "mov %c4(%%rdx), %%rbx;"
        "mov %c5(%%rdx), %%rbp;"
        "mov %c6(%%rdx), %%r10;"
        "mov %c7(%%rdx), %%r11;"
        "mov %c8(%%rdx), %%r12;"
        "mov %c9(%%rdx), %%r13;"
        "mov %c10(%%rdx), %%r14;"
        "mov %c11(%%rdx), %%r15;"
        "mov %c12(%%rdx), %%rcx;"
        "push %%rcx;"
        "mov %c13(%%rdx), %%rcx;"
        "push %%rcx;"
        "mov %c14(%%rdx), %%rax;"
        "mov %c15(%%rdx), %%rsi;"
        "mov %c16(%%rdx), %%rdi;"
        "mov %c17(%%rdx), %%rcx;"
        "mov %c18(%%rdx), %%r8;"
        "mov %c19(%%rdx), %%r9;"
        "mov %c20(%%rdx), %%rdx;"
        "popfq;"
        "ret;"
        ::
        "r"(&context),
        "i"(offsetof(context_t, fp_regs)),
        "i"(offsetof(context_t, fp_regs.mxcsr)),
        "i"(offsetof(context_t, regs.rsp)),
        "i"(offsetof(context_t, regs.rbx)),
        "i"(offsetof(context_t, regs.rbp)),
        "i"(offsetof(context_t, regs.r10)),
        "i"(offsetof(context_t, regs.r11)),
        "i"(offsetof(context_t, regs.r12)),
        "i"(offsetof(context_t, regs.r13)),
        "i"(offsetof(context_t, regs.r14)),
        "i"(offsetof(context_t, regs.r15)),
        "i"(offsetof(context_t, regs.rip)),
        "i"(offsetof(context_t, regs.eflags)),
        "i"(offsetof(context_t, regs.rax)),
        "i"(offsetof(context_t, regs.rsi)),
        "i"(offsetof(context_t, regs.rdi)),
        "i"(offsetof(context_t, regs.rcx)),
        "i"(offsetof(context_t, regs.r8)),
        "i"(offsetof(context_t, regs.r9)),
        "i"(offsetof(context_t, regs.rdx))
    );
#else
    z_exit_group(status);
#endif
}

void *quit_p() {
    return &quit;
}
