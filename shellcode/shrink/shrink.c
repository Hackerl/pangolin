#include "shrink.h"
#include <z_memory.h>

void shrink_main(void *ptr) {
    z_free(ptr);
}

void __attribute__ ((visibility ("default"))) shellcode_start() {
#if __i386__ || __x86_64__
    asm volatile("nop; nop; call shrink_main; int3;");
#elif __arm__
    asm volatile("nop; bl shrink_main; .inst 0xe7f001f0;");
#elif __aarch64__
    asm volatile("nop; bl shrink_main; .inst 0xd4200000;");
#else
#error "unknown arch"
#endif
}
