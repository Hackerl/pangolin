#include "log.h"
#include "elf_loader.h"
#include "loader.h"

void __attribute__ ((visibility ("default"))) shellcode_begin() {}

void loader_main(void *ptr) {
    LOG("elf loader start");

    struct CLoaderArgs *loader_args = ptr;
    elf_loader(loader_args);

    __exit(0);
}

void __attribute__ ((visibility ("default"))) shellcode_start() {
    asm volatile("nop; nop; call %P0; int3;" :: "i" (loader_main));
}

void __attribute__ ((visibility ("default"))) shellcode_end() {}
