#ifndef PANGOLIN_ELF_LOADER_H
#define PANGOLIN_ELF_LOADER_H

#include "payload.h"

struct CLoaderContext {
    unsigned long base;
    unsigned long entry;
    unsigned long header;
    unsigned long header_num;
    unsigned long header_size;
};

unsigned long load_segments(void *buffer);

int elf_map(const char *path, struct CLoaderContext *ctx);
int elf_loader(struct CPayload *payload);

#endif //PANGOLIN_ELF_LOADER_H
