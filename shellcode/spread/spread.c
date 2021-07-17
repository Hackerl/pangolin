#include "spread.h"
#include <z_memory.h>
#include <z_syscall.h>
#include <sys/mman.h>
#include <sys/user.h>

void __attribute__ ((visibility ("default"))) shellcode_begin() {

}

void *spread_main(unsigned long size) {
    if (!size)
        return NULL;

    void *mem = z_malloc(size);

    if (!mem)
        return NULL;

    unsigned long minVA = (unsigned long)mem & ~(PAGE_SIZE - 1);
    unsigned long maxVA = ((unsigned long)mem + size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

    if (z_mprotect((void *)minVA, maxVA - minVA, PROT_READ | PROT_EXEC | PROT_WRITE) < 0) {
        z_free(mem);
        return NULL;
    }

    return mem;
}

void __attribute__ ((visibility ("default"))) shellcode_start() {
    asm volatile("nop; nop; call spread_main; int3;");
}

void __attribute__ ((visibility ("default"))) shellcode_end() {}
