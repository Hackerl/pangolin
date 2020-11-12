#ifndef PANGOLIN_ELF_LOADER_H
#define PANGOLIN_ELF_LOADER_H

#include "args.h"
#include <elf.h>

void elf_loader(struct CLoaderArgs* loader_args);

int elf_map(char *path, unsigned long base_address, unsigned long *auxv, unsigned long *out_eop);
int load_segment(unsigned char *elf, Elf64_Ehdr *elf_hdr, Elf64_Phdr *p_hdr, unsigned long base_offset);

#endif //PANGOLIN_ELF_LOADER_H
