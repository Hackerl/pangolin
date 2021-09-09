#include <z_memory.h>

void main(void *ptr) {
    z_free(ptr);
}

#if __i386__ || __x86_64__

__asm__ (
".section .entry\n"
".global entry\n"
"entry:\n"
"    nop\n"
"    nop\n"
"    call main\n"
"    int3"
);

#elif __arm__

__asm__ (
".section .entry\n"
".global entry\n"
"entry:\n"
"    nop\n"
"    bl main\n"
"    .inst 0xe7f001f0"
);

#elif __aarch64__

__asm__ (
".section .entry\n"
".global entry\n"
"entry:\n"
"    nop\n"
"    bl main\n"
"    .inst 0xd4200000"
);

#else
#error "unknown arch"
#endif
