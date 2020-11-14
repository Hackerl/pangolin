#include "spread.h"
#include <crt_asm.h>
#include <crt_memory.h>

void __attribute__ ((visibility ("default"))) shellcode_begin() {}

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
    INJ_ENTRY(spread_main);
}

void __attribute__ ((visibility ("default"))) shellcode_end() {}
