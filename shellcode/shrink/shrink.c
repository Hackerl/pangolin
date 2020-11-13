#include "shrink.h"
#include <crt_memory.h>

void __attribute__ ((visibility ("default"))) shellcode_begin() {}


void shrink_main(void *ptr) {
    free(ptr);
}

void __attribute__ ((visibility ("default"))) shellcode_start() {
    asm volatile("nop; nop; call %P0; int3;" :: "i" (shrink_main));
}

void __attribute__ ((visibility ("default"))) shellcode_end() {}
