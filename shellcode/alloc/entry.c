#include <z_syscall.h>
#include <sys/mman.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

#define ALLOC_SIZE 0x21000

void *main() {
    return Z_RESULT_V(z_mmap(
            NULL,
            ALLOC_SIZE,
            PROT_READ | PROT_EXEC | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE,
            -1,
            0
    ));
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
