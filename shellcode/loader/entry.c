#include "payload.h"
#include "elf_loader.h"
#include <z_log.h>
#include <z_memory.h>
#include <z_syscall.h>
#include <z_std.h>
#include <fcntl.h>
#include <asm/prctl.h>

#define STACK_SIZE 0x21000
#define STATUS_PATH "/proc/self/status"
#define TRACER_FIELD "TracerPid"

static regs_t *snapshot = NULL;

void terminate(int status) {
    int fd = Z_RESULT_V(z_open(STATUS_PATH, O_RDONLY, 0));

    if (fd < 0)
        z_exit_group(status);

    char buffer[1024] = {};
    ssize_t length = Z_RESULT_V(z_read(fd, buffer, sizeof(buffer)));

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

    LOG("restore snapshot: %p", snapshot);

#ifdef __x86_64__
    if (Z_RESULT_V(z_arch_prctl(ARCH_SET_FS, snapshot->fs_base)) < 0)
        z_exit_group(status);

    if (Z_RESULT_V(z_arch_prctl(ARCH_SET_GS, snapshot->gs_base)) < 0)
        z_exit_group(status);

    asm volatile(
        "mov %0, %%rdx;"
        "mov %c1(%%rdx), %%rsp;"
        "mov %c2(%%rdx), %%rbx;"
        "mov %c3(%%rdx), %%rbp;"
        "mov %c4(%%rdx), %%r12;"
        "mov %c5(%%rdx), %%r13;"
        "mov %c6(%%rdx), %%r14;"
        "mov %c7(%%rdx), %%r15;"
        "mov %c8(%%rdx), %%rcx;"
        "push %%rcx;"
        "mov %c9(%%rdx), %%rax;"
        "mov %c10(%%rdx), %%rsi;"
        "mov %c11(%%rdx), %%rdi;"
        "mov %c12(%%rdx), %%rcx;"
        "mov %c13(%%rdx), %%r8;"
        "mov %c14(%%rdx), %%r9;"
        "mov %c15(%%rdx), %%rdx;"
        "ret;"
        ::
        "r"(snapshot),
        "i"(offsetof(regs_t, rsp)),
        "i"(offsetof(regs_t, rbx)),
        "i"(offsetof(regs_t, rbp)),
        "i"(offsetof(regs_t, r12)),
        "i"(offsetof(regs_t, r13)),
        "i"(offsetof(regs_t, r14)),
        "i"(offsetof(regs_t, r15)),
        "i"(offsetof(regs_t, rcx)),
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

void main(void *ptr) {
    loader_payload_t *payload = (loader_payload_t *)ptr;
    snapshot = &payload->regs;

    if (!payload->daemon) {
        int status = elf_loader(payload);
        terminate(status);
    }

    char *stack = z_malloc(STACK_SIZE);

    if (!stack) {
        LOG("malloc failed");
        terminate(-1);
    }

    z_memcpy(stack, payload, sizeof(loader_payload_t));

#ifdef __i386__
    asm volatile(
            "mov %0, %%esp;"
            "push %1;"
            "call elf_loader;"
            "push %%eax;"
            "call terminate;"
            ::
            "r"(stack + STACK_SIZE),
            "r"(stack));
#elif __x86_64__
    asm volatile(
            "mov %0, %%rsp;"
            "mov %1, %%rdi;"
            "call elf_loader;"
            "mov %%rax, %%rdi;"
            "call terminate;"
            ::
            "r"(stack + STACK_SIZE),
            "r"(stack));
#elif __arm__
    asm volatile(
            "mov %%sp, %0;"
            "mov %%r0, %1;"
            "bl elf_loader;"
            "bl terminate;"
            ::
            "r"(stack + STACK_SIZE),
            "r"(stack));
#elif __aarch64__
    asm volatile(
            "mov sp, %[stack];"
            "mov x0, %[argument];"
            "bl elf_loader;"
            "bl terminate;"
            ::
            [stack] "r"(stack + STACK_SIZE),
            [argument] "r"(stack));
#endif
}

#if __i386__ || __x86_64__

__asm__ (
".section .entry;"
".global entry;"
"entry:"
"    nop;"
"    nop;"
"    call main;"
"    int3"
);

#elif __arm__

__asm__ (
".section .entry;"
".global entry;"
"entry:"
"    nop;"
"    bl main;"
"    .inst 0xe7f001f0"
);

#elif __aarch64__

__asm__ (
".section .entry;"
".global entry;"
"entry:"
"    nop;"
"    bl main;"
"    .inst 0xd4200000"
);

#else
#error "unknown arch"
#endif
