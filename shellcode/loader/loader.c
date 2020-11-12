#include <sys/user.h>

void __attribute__ ((visibility ("default"))) *loader_begin() {}

#include "log.h"
#include "elf_loader.h"

void loader_main(void *ptr) {
    LOG("loader shellcode");

    struct CLoaderArgs *loader_args = ptr;
    elf_loader(loader_args);

    __exit(0);
}

void __attribute__ ((visibility ("default"))) loader_self(void *ptr) {
    loader_main(ptr);
}

void __attribute__ ((visibility ("default"))) loader_start() {
    asm volatile("nop; nop; call %P0; int3;" :: "i" (loader_main));
}

void __attribute__ ((visibility ("default"))) *loader_end() {
    char * endString = "end";
    unsigned long endAddress = (unsigned long)endString;

    endAddress += PAGE_SIZE - (endAddress % PAGE_SIZE);
    return (void *)endAddress;
}
