#include <z_memory.h>
#include <z_syscall.h>
#include <sys/mman.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

void *main(unsigned long size) {
    if (!size)
        return NULL;

    void *mem = z_malloc(size);

    if (!mem)
        return NULL;

    unsigned long minVA = (unsigned long)mem & ~(PAGE_SIZE - 1);
    unsigned long maxVA = ((unsigned long)mem + size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    if (Z_RESULT_V(z_mprotect((void *)minVA, maxVA - minVA, PROT_READ | PROT_EXEC | PROT_WRITE)) < 0) {
        z_free(mem);
        return NULL;
    }

    return mem;
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