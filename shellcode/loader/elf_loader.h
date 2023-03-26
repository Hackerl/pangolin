#ifndef PANGOLIN_ELF_LOADER_H
#define PANGOLIN_ELF_LOADER_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uintptr_t base;
    uintptr_t entry;
    uintptr_t header;
    size_t header_num;
    size_t header_size;
} elf_context_t;

int load_elf_file(const char *path, elf_context_t ctx[2]);
int jump_to_entry(const elf_context_t ctx[2], int argc, char *argv[], char *envp[]);

#endif //PANGOLIN_ELF_LOADER_H
