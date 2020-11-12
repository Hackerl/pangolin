void __attribute__ ((visibility ("default"))) shrink_begin() {}

#include <crt_memory.h>

void shrink_main(void *ptr) {
    free(ptr);
}

void __attribute__ ((visibility ("default"))) shrink_start() {
    asm volatile("nop; nop; call %P0; int3;" :: "i" (shrink_main));
}

void __attribute__ ((visibility ("default"))) shrink_end() {}
