#include "spread.h"

void __attribute__ ((visibility ("default"))) shellcode_begin() {}

#include <crt_memory.h>

void *spread_main(unsigned long size) {
    if (!size)
        return NULL;

    void * mem = malloc(size);

    if (!mem)
        return NULL;

    if (_mprotect(mem - CRT_SIZE_HDR, CRT_SIZE_ALLOC(mem), PROT_READ | PROT_EXEC | PROT_WRITE) < 0) {
        free(mem);
        return NULL;
    }

    return mem;
}

void __attribute__ ((visibility ("default"))) shellcode_start() {
    asm volatile("nop; nop; call %P0; int3;" :: "i" (spread_main));
}

void __attribute__ ((visibility ("default"))) shellcode_end() {}
