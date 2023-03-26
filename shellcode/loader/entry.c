#include "payload.h"
#include "elf_loader.h"
#include <z_log.h>
#include <z_memory.h>
#include <z_std.h>

#define STACK_SIZE 0x21000

int load(loader_payload_t *payload) {
    int argc = 0;

    char *argv[PAYLOAD_MAX_ARG];
    char *envp[PAYLOAD_MAX_ENV];

    z_memset(argv, 0, sizeof(argv));
    z_memset(envp, 0, sizeof(envp));

    if (!z_strlen(payload->argv)) {
        LOG("empty argv");
        return -1;
    }

    argv[argc++] = payload->argv;

    for (char *i = payload->argv; *i && argc < PAYLOAD_MAX_ARG; i++) {
        if (*i == *PAYLOAD_DELIMITER) {
            *i = 0;
            argv[argc++] = i + 1;
        }
    }

    if (z_strlen(payload->env)) {
        int count = 0;
        envp[count++] = payload->env;

        for (char *i = payload->env; *i && count < PAYLOAD_MAX_ENV - 1; i++) {
            if (*i == *PAYLOAD_DELIMITER) {
                *i = 0;
                envp[count++] = i + 1;
            }
        }
    }

    for (int i = 0; i < argc; i++)
        LOG("arg[%d] %s", i, argv[i]);

    for (char **e = envp; *e != NULL; e++)
        LOG("env %s", *e);

    const char *path = argv[0];

    elf_context_t ctx[2];
    z_memset(ctx, 0, sizeof(ctx));

    if (load_elf_file(path, ctx) < 0) {
        LOG("elf mapping failed: %s", path);
        return -1;
    }

    return jump_to_entry(ctx, argc, argv, envp);
}

void main(loader_payload_t *payload) {
    snapshot(&payload->context);

    if (!payload->daemon) {
        int status = load(payload);
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
            "call load;"
            "push %%eax;"
            "call quit;"
            ::
            "r"(stack + STACK_SIZE),
            "r"(stack));
#elif __x86_64__
    asm volatile(
            "mov %0, %%rsp;"
            "mov %1, %%rdi;"
            "call load;"
            "mov %%rax, %%rdi;"
            "call quit;"
            ::
            "r"(stack + STACK_SIZE),
            "r"(stack));
#elif __arm__
    asm volatile(
            "mov %%sp, %0;"
            "mov %%r0, %1;"
            "bl load;"
            "bl quit;"
            ::
            "r"(stack + STACK_SIZE),
            "r"(stack));
#elif __aarch64__
    asm volatile(
            "mov sp, %[stack];"
            "mov x0, %[argument];"
            "bl load;"
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
