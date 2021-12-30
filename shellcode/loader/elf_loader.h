#ifndef PANGOLIN_ELF_LOADER_H
#define PANGOLIN_ELF_LOADER_H

#include "payload.h"

typedef struct {
    unsigned long base;
    unsigned long entry;
    unsigned long header;
    unsigned long header_num;
    unsigned long header_size;
} elf_context_t;

typedef struct {
    unsigned long base;
    unsigned long minVA;
    unsigned long maxVA;
} elf_image_t;

int load_segments(char *buffer, int fd, elf_image_t *image);

int elf_map(const char *path, elf_context_t *ctx);
int elf_loader(loader_payload_t *payload);

#endif //PANGOLIN_ELF_LOADER_H
