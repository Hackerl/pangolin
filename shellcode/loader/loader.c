#include "loader.h"
#include "payload.h"
#include "elf_loader.h"
#include <z_log.h>
#include <z_memory.h>
#include <z_syscall.h>
#include <z_std.h>

#define STACK_SIZE 0x20000

void loader_main(void *ptr) {
    struct CPayload *payload = (struct CPayload *)ptr;

    if (!payload->daemon) {
        int status = elf_loader(payload);
        z_exit(status);
    }

    char *stack = z_malloc(STACK_SIZE);

    if (!stack) {
        LOG("malloc failed");
        z_exit(-1);
    }

    z_memcpy(stack, payload, sizeof(struct CPayload));

#ifdef __i386__
    asm volatile(
            "mov %0, %%esp;"
            "push %1;"
            "call elf_loader;"
            "push %%eax;"
            "call z_exit;"
            ::
            "r"(stack + STACK_SIZE),
            "r"(stack));
#elif __x86_64__
    asm volatile(
            "mov %0, %%rsp;"
            "mov %1, %%rdi;"
            "call elf_loader;"
            "mov %%rax, %%rdi;"
            "call z_exit;"
            ::
            "r"(stack + STACK_SIZE),
            "r"(stack));
#elif __arm__
    asm volatile(
            "mov %%sp, %0;"
            "mov %%r0, %1;"
            "bl elf_loader;"
            "bl z_exit;"
            ::
            "r"(stack + STACK_SIZE),
            "r"(stack));
#elif __aarch64__
    asm volatile(
            "mov sp, %[stack];"
            "mov x0, %[argument];"
            "bl elf_loader;"
            "bl z_exit;"
            ::
            [stack] "r"(stack + STACK_SIZE),
            [argument] "r"(stack));
#else
#error "unknown arch"
#endif
}

void __attribute__ ((visibility ("default"))) entry() {
#if __i386__ || __x86_64__
    asm volatile("nop; nop; call loader_main; int3;");
#elif __arm__
    asm volatile("nop; bl loader_main; .inst 0xe7f001f0;");
#elif __aarch64__
    asm volatile("nop; bl loader_main; .inst 0xd4200000;");
#else
#error "unknown arch"
#endif
}
