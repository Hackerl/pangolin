#include "shrink.h"
#include <crt_asm.h>
#include <crt_memory.h>

void __attribute__ ((visibility ("default"))) shellcode_begin() {}


void shrink_main(void *ptr) {
    free(ptr);
}

void __attribute__ ((visibility ("default"))) shellcode_start() {
    INJ_ENTRY(shrink_main);
}

void __attribute__ ((visibility ("default"))) shellcode_end() {}
