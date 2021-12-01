#include "payload.h"
#include "elf_loader.h"
#include <z_log.h>
#include <z_memory.h>
#include <z_std.h>

#define STACK_SIZE 0x21000

void main(void *ptr) {
    loader_payload_t *payload = (loader_payload_t *)ptr;
    snapshot(&payload->regs);

    if (!payload->daemon) {
        int status = elf_loader(payload);
        quit(status);
    }

    char *stack = z_malloc(STACK_SIZE);

    if (!stack) {
        LOG("malloc failed");
        quit(-1);
    }

    z_memcpy(stack, payload, sizeof(loader_payload_t));

#ifdef __i386__
    asm volatile(
            "mov %0, %%esp;"
            "push %1;"
            "call elf_loader;"
            "push %%eax;"
            "call quit;"
            ::
            "r"(stack + STACK_SIZE),
            "r"(stack));
#elif __x86_64__
    asm volatile(
            "mov %0, %%rsp;"
            "mov %1, %%rdi;"
            "call elf_loader;"
            "mov %%rax, %%rdi;"
            "call quit;"
            ::
            "r"(stack + STACK_SIZE),
            "r"(stack));
#elif __arm__
    asm volatile(
            "mov %%sp, %0;"
            "mov %%r0, %1;"
            "bl elf_loader;"
            "bl quit;"
            ::
            "r"(stack + STACK_SIZE),
            "r"(stack));
#elif __aarch64__
    asm volatile(
            "mov sp, %[stack];"
            "mov x0, %[argument];"
            "bl elf_loader;"
            "bl quit;"
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
