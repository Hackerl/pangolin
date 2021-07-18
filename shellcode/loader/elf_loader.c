#include "elf_loader.h"
#include <z_std.h>
#include <z_log.h>
#include <z_syscall.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <fcntl.h>

#define STACK_ALIGN     16

#define PROGRAM         0
#define INTERPRETER     1

#define AV_PATH         "/proc/self/auxv"

#define ROUND_PG(x)     (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x)     ((x) & ~(PAGE_SIZE - 1))

unsigned long load_segments(void *buffer) {
    Elf64_Ehdr *ehdr = buffer;
    Elf64_Phdr *phdr = buffer + ehdr->e_phoff;

    unsigned long minVA = -1;
    unsigned long maxVA = 0;

    for (Elf64_Phdr *i = phdr; i < &phdr[ehdr->e_phnum]; i++) {
        if (i->p_type != PT_LOAD)
            continue;

        if (i->p_vaddr < minVA)
            minVA = i->p_vaddr;

        if (i->p_vaddr + i->p_memsz > maxVA)
            maxVA = i->p_vaddr + i->p_memsz;
    }

    minVA = TRUNC_PG(minVA);
    maxVA = ROUND_PG(maxVA);

    int dyn = ehdr->e_type == ET_DYN;

    void *base = z_mmap(
            dyn ? NULL : (void *)minVA,
            maxVA - minVA,
            PROT_NONE,
            (dyn ? 0 : MAP_FIXED) | MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0);

    if (base == MAP_FAILED) {
        LOG("mmap failed: %d", z_errno);
        return -1;
    }

    z_munmap(base, maxVA - minVA);

    LOG("segment base: 0x%lx[0x%lx]", base, maxVA - minVA);

    for (Elf64_Phdr *i = phdr; i < &phdr[ehdr->e_phnum]; i++) {
        if (i->p_type != PT_LOAD)
            continue;

        unsigned long offset = i->p_vaddr & (PAGE_SIZE - 1);
        unsigned long start = (dyn ? (unsigned long)base : 0) + TRUNC_PG(i->p_vaddr);
        unsigned long size = ROUND_PG(i->p_memsz + offset);

        LOG("segment: 0x%lx[0x%lx]", start, size);

        void *p = z_mmap(
                (void *)start,
                size,
                PROT_WRITE,
                MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
                -1,
                0);

        if (p == MAP_FAILED) {
            z_munmap(base, maxVA - minVA);
            return -1;
        }

        z_memcpy((unsigned char *)p + offset, buffer + i->p_offset, i->p_filesz);

        unsigned int flags = i->p_flags;
        int protection = (flags & PF_R ? PROT_READ : 0) | (flags & PF_W ? PROT_WRITE : 0) | (flags & PF_X ? PROT_EXEC : 0);

        if (z_mprotect(p, size, protection) == -1) {
            z_munmap(base, maxVA - minVA);
            return -1;
        }
    }

    return (unsigned long)base;
}

int elf_check(Elf64_Ehdr *ehdr) {
    if (
            ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
            ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
            ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
            ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        LOG("elf magic error");
        return -1;
    }

    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64 || ehdr->e_ident[EI_VERSION] != EV_CURRENT) {
        LOG("elf class error");
        return -1;
    }

    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
        LOG("elf type error");
        return -1;
    }

    return 0;
}

int elf_map(const char *path, struct CLoaderContext *ctx) {
    struct stat sb = {};

    if (z_stat(path, &sb) < 0) {
        LOG("stat file failed: %s", path);
        return -1;
    }

    if ((sb.st_mode & S_IFREG) == 0) {
        LOG("file type invalid: %s", path);
        return -1;
    }

    int fd = z_open(path, O_RDONLY, 0);

    if (fd < 0) {
        LOG("open failed: %s %d", path, z_errno);
        return -1;
    }

    long size = z_lseek(fd, 0, SEEK_END);

    if (size < 0) {
        z_close(fd);
        return -1;
    }

    void *buffer = z_mmap(NULL, (size_t)size, PROT_READ, MAP_PRIVATE, fd, 0);

    if (buffer == MAP_FAILED) {
        z_close(fd);
        return -1;
    }

    z_close(fd);

    if (elf_check(buffer) < 0) {
        z_munmap(buffer, (size_t)size);
        return -1;
    }

    Elf64_Ehdr *ehdr = buffer;
    Elf64_Phdr *phdr = buffer + ehdr->e_phoff;

    for (Elf64_Phdr *i = phdr; i < &phdr[ehdr->e_phnum]; i++) {
        if (i->p_type == PT_INTERP) {
            const char *interpreter = buffer + i->p_offset;

            if (elf_map(interpreter, ctx + 1) < 0) {
                LOG("mapping interpreter failed: %s", interpreter);
                z_munmap(buffer, (size_t)size);

                return -1;
            }

            break;
        }
    }

    LOG("mapping %s", path);

    unsigned long base = load_segments(buffer);

    if (base == -1) {
        z_munmap(buffer, (size_t)size);
        return -1;
    }

    ctx->base = base;
    ctx->entry = ehdr->e_entry + (ehdr->e_type == ET_DYN ? base : 0);
    ctx->header = base + ehdr->e_phoff;
    ctx->header_num = ehdr->e_phnum;
    ctx->header_size = ehdr->e_phentsize;

    z_munmap(buffer, (size_t)size);

    return 0;
}

int elf_loader(struct CPayload *payload) {
    int argc = 0;

    char *argv[PAYLOAD_MAX_ARG] = {};
    char *env[PAYLOAD_MAX_ENV] = {};

    if (!z_strlen(payload->argv)) {
        LOG("empty argv");
        return -1;
    }

    argv[argc++] = payload->argv;

    for (char *i = payload->argv; *i && argc < PAYLOAD_MAX_ARG; i++) {
        if (*i == *PAYLOAD_DELIMITER) {
            *i = 0;
            argv[argc++] = i + 1;
        }
    }

    if (z_strlen(payload->env)) {
        int count = 0;
        env[count++] = payload->env;

        for (char *i = payload->env; *i && count < PAYLOAD_MAX_ENV; i++) {
            if (*i == *PAYLOAD_DELIMITER) {
                *i = 0;
                env[count++] = i + 1;
            }
        }
    }

    for(int i = 0; i < argc; i++)
        LOG("arg[%d] %s", i, argv[i]);

    for(char **e = env; *e != NULL; e++)
        LOG("env %s", *e);

    const char *path = argv[0];
    struct CLoaderContext context[2] = {};

    if (elf_map(path, context) < 0) {
        LOG("elf mapping failed: %s", path);
        return -1;
    }

    int fd = z_open(AV_PATH, O_RDONLY, 0);

    if (fd < 0) {
        LOG("open failed: %d", z_errno);
        return -1;
    }

    char av[1024] = {};

    ssize_t length = z_read(fd, av, sizeof(av));

    if (length == -1) {
        z_close(fd);
        return -1;
    }

    z_close(fd);

    for (Elf64_auxv_t *i = (Elf64_auxv_t *)av; i->a_type != AT_NULL; i++) {
        switch (i->a_type) {
            case AT_PHDR:
                i->a_un.a_val = context[PROGRAM].header;
                break;

            case AT_PHENT:
                i->a_un.a_val = context[PROGRAM].header_size;
                break;

            case AT_PHNUM:
                i->a_un.a_val = context[PROGRAM].header_num;
                break;

            case AT_BASE:
                i->a_un.a_val = context[INTERPRETER].base ? context[INTERPRETER].base : 0;
                break;

            case AT_ENTRY:
                i->a_un.a_val = context[PROGRAM].entry;
                break;

            case AT_EXECFN:
                i->a_un.a_val = (unsigned long)path;
                break;
        }
    }

    unsigned char buffer[4096] = {};
    unsigned long entry = context[INTERPRETER].entry ? context[INTERPRETER].entry : context[PROGRAM].entry;

    unsigned char *stack = (unsigned char *)(((unsigned long)buffer + STACK_ALIGN - 1) & ~(STACK_ALIGN - 1));
    unsigned long *p = (unsigned long *)stack;

    *(int *)p++ = argc;

    for (int i = 0; i < argc; i++)
        *(char **)p++ = argv[i];

    *(char **)p++ = NULL;

    for (char ** i = env; *i; i++)
        *(char **)p++ = *i;

    *(char **)p++ = NULL;

    z_memcpy(p, av, length);

    asm volatile("mov %0, %%rsp; xor %%rdx, %%rdx; jmp *%1;" :: "r"(stack), "a"(entry));

    return 0;
}