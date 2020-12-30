#include "elf_loader.h"
#include "loader.h"
#include <crt_log.h>
#include <crt_asm.h>

#define STACK_SIZE 0x20000

void __attribute__ ((visibility ("default"))) shellcode_begin() {}

void loader_main(void *ptr) {
    LOG("elf loader start");

    char *stack = malloc(STACK_SIZE);
    char *stack_top = stack + STACK_SIZE;

    FIX_SP_JMP(stack_top, elf_loader, ptr);
}

void __attribute__ ((visibility ("default"))) shellcode_start() {
    INJ_ENTRY(loader_main);
}

void __attribute__ ((visibility ("default"))) shellcode_end() {}
