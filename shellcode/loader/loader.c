#include "loader.h"
#include "payload.h"
#include "elf_loader.h"
#include <z_log.h>
#include <z_memory.h>
#include <z_syscall.h>
#include <z_std.h>

#define STACK_SIZE 0x20000

void __attribute__ ((visibility ("default"))) shellcode_begin() {

}

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

    asm volatile(
            "mov %0, %%rsp;"
            "mov %1, %%rdi;"
            "call *%2;"
            "mov %%rax, %%rdi;"
            "call z_exit;"
            ::
            "r"(stack + STACK_SIZE),
            "r"(stack),
            "a"(elf_loader));
}

void __attribute__ ((visibility ("default"))) shellcode_start() {
    asm volatile("nop; nop; call loader_main; int3;");
}

void __attribute__ ((visibility ("default"))) shellcode_end() {

}
