#include "quit.h"
#include <z_std.h>
#include <z_syscall.h>
#include <z_log.h>
#include <fcntl.h>
#include <asm/prctl.h>

#define STATUS_PATH "/proc/self/status"
#define TRACER_FIELD "TracerPid"

static regs_t regs_snapshot = {};

void snapshot(regs_t *regs) {
    z_memcpy(&regs_snapshot, regs, sizeof(regs_t));
}

void quit(int status) {
    int fd = Z_RESULT_V(z_open(STATUS_PATH, O_RDONLY, 0));

    if (fd < 0)
        z_exit_group(status);

    char buffer[1024] = {};
    ssize_t length = Z_RESULT_V(z_read(fd, buffer, sizeof(buffer) - 1));

    if (length < 0) {
        z_close(fd);
        z_exit_group(status);
    }

    z_close(fd);

    char *p = z_memmem(buffer, length, TRACER_FIELD, z_strlen(TRACER_FIELD));

    if (!p)
        z_exit_group(status);

    pid_t pid = (pid_t)z_strtoul(p + z_strlen(TRACER_FIELD) + 2, NULL, 10);

    if (pid != 0 && Z_RESULT_V(z_kill(pid, 0)) == 0)
        z_exit_group(status);

    LOG("restore snapshot");

#ifdef __x86_64__
    if (Z_RESULT_V(z_arch_prctl(ARCH_SET_FS, regs_snapshot.fs_base)) < 0)
        z_exit_group(status);

    if (Z_RESULT_V(z_arch_prctl(ARCH_SET_GS, regs_snapshot.gs_base)) < 0)
        z_exit_group(status);

    asm volatile(
        "mov %0, %%rdx;"
        "mov %c1(%%rdx), %%rsp;"
        "mov %c2(%%rdx), %%rbx;"
        "mov %c3(%%rdx), %%rbp;"
        "mov %c4(%%rdx), %%r10;"
        "mov %c5(%%rdx), %%r11;"
        "mov %c6(%%rdx), %%r12;"
        "mov %c7(%%rdx), %%r13;"
        "mov %c8(%%rdx), %%r14;"
        "mov %c9(%%rdx), %%r15;"
        "mov %c10(%%rdx), %%rcx;"
        "push %%rcx;"
        "mov %c11(%%rdx), %%rcx;"
        "push %%rcx;"
        "mov %c12(%%rdx), %%rax;"
        "mov %c13(%%rdx), %%rsi;"
        "mov %c14(%%rdx), %%rdi;"
        "mov %c15(%%rdx), %%rcx;"
        "mov %c16(%%rdx), %%r8;"
        "mov %c17(%%rdx), %%r9;"
        "mov %c18(%%rdx), %%rdx;"
        "popfq;"
        "ret;"
        ::
        "r"(&regs_snapshot),
        "i"(offsetof(regs_t, rsp)),
        "i"(offsetof(regs_t, rbx)),
        "i"(offsetof(regs_t, rbp)),
        "i"(offsetof(regs_t, r10)),
        "i"(offsetof(regs_t, r11)),
        "i"(offsetof(regs_t, r12)),
        "i"(offsetof(regs_t, r13)),
        "i"(offsetof(regs_t, r14)),
        "i"(offsetof(regs_t, r15)),
        "i"(offsetof(regs_t, rip)),
        "i"(offsetof(regs_t, eflags)),
        "i"(offsetof(regs_t, rax)),
        "i"(offsetof(regs_t, rsi)),
        "i"(offsetof(regs_t, rdi)),
        "i"(offsetof(regs_t, rcx)),
        "i"(offsetof(regs_t, r8)),
        "i"(offsetof(regs_t, r9)),
        "i"(offsetof(regs_t, rdx))
    );
#else
    z_exit_group(status);
#endif
}