#include "log.h"
#include "elf_loader.h"
#include "fake_stack.h"
#include <crt_syscall.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stddef.h>
#include <sys/user.h>

#define MOD_OFFSET_NEXT     0x10000
#define ALIGN_PAGE_UP(x)    do { if((x) % PAGE_SIZE) (x) += (PAGE_SIZE - ((x) % PAGE_SIZE)); } while(0)
#define ALIGN_PAGE_DOWN(x)  do { if((x) % PAGE_SIZE) (x) -= ((x) % PAGE_SIZE); } while(0)

int set_auxv(unsigned long * auxv, unsigned long at_type, unsigned long at_val) {
    int i = 0;

    while (auxv[i] && auxv[i] != at_type)
        i += 2;

    if (!auxv[i]) {
        LOG("set auxv failed");
        return -1;
    }

    auxv[i+1] = at_val;

    return 0;
}

int elf_map(char *path, unsigned long base_address, unsigned long *auxv, unsigned long *out_eop) {
    LOG("map elf");

    int fd = _open(path, O_RDONLY, 0);

    if (fd < 0) {
        LOG("open elf failed");
        return -1;
    }

    long file_size = _lseek(fd, 0, SEEK_END);

    if(file_size <= 0) {
        LOG("seek file end failed");
        _close(fd);
        return -1;
    }

    _lseek(fd, 0, SEEK_SET);

    void *elf_buffer = _mmap(NULL, (size_t)file_size, PROT_READ, MAP_PRIVATE, fd, 0);

    if (!elf_buffer) {
        _close(fd);
        return -1;
    }

    _close(fd);

    unsigned long base_offset = 0;

    Elf64_Ehdr* elf_hdr = (Elf64_Ehdr*)elf_buffer;

    if (elf_hdr->e_type == ET_DYN)
        base_offset = base_address;

    unsigned long eop_elf = base_offset + elf_hdr->e_entry;

    unsigned long base_segment  = 0;
    unsigned long base_next = 0;

    for (int i = 0; i < elf_hdr->e_phnum; i++) {
        Elf64_Phdr *p_hdr = (Elf64_Phdr *)(elf_buffer + elf_hdr->e_phoff + i * elf_hdr->e_phentsize);

        if (p_hdr->p_type == PT_LOAD && load_segment(elf_buffer, elf_hdr, p_hdr, base_offset)) {
            _munmap(elf_buffer, (int)file_size);
            return -1;
        }

        if (!base_segment)
            base_segment = p_hdr->p_vaddr;

        base_next = p_hdr->p_vaddr + p_hdr->p_memsz > base_next ? p_hdr->p_vaddr + p_hdr->p_memsz : base_next;
    }

    ALIGN_PAGE_DOWN(base_segment);

    if (elf_hdr->e_type == ET_DYN)
        base_segment += base_offset;

    base_next += MOD_OFFSET_NEXT;
    ALIGN_PAGE_UP(base_next);

    unsigned long eop_ldr = 0;
    unsigned long base_interpreter = 0;

    for (int i = 0; i < elf_hdr->e_phnum; i++) {
        Elf64_Phdr *p_hdr = (Elf64_Phdr *)(elf_buffer + elf_hdr->e_phoff + i * elf_hdr->e_phentsize);

        if (p_hdr->p_type != PT_INTERP)
            continue;

        base_interpreter = base_address + base_next;
        char *interpreter = (char*)(elf_hdr->e_type == ET_DYN ? base_segment : 0) + p_hdr->p_vaddr;

        if (elf_map(interpreter, base_interpreter, NULL, &eop_ldr)) {
            _munmap(elf_buffer, (int)file_size);
            return -1;
        }
    }

    if (auxv) {
        set_auxv(auxv, AT_PHDR, base_segment + elf_hdr->e_phoff);
        set_auxv(auxv, AT_PHNUM, elf_hdr->e_phnum);
        set_auxv(auxv, AT_ENTRY, eop_elf);
        set_auxv(auxv, AT_BASE, base_segment);
    }

    LOG("map elf success");

    _munmap(elf_buffer, (int)file_size);
    *out_eop = eop_ldr ? eop_ldr : eop_elf;

    return 0;
}

int load_segment(unsigned char *elf, Elf64_Ehdr *elf_hdr, Elf64_Phdr *p_hdr, unsigned long base_offset) {
    unsigned long seg_address = p_hdr->p_vaddr + base_offset;
    unsigned long seg_length  = p_hdr->p_memsz;
    unsigned long seg_offset  = seg_address & (PAGE_SIZE - 1);

    ALIGN_PAGE_UP(seg_length);

    unsigned long address = (unsigned long)_mmap((void*)(seg_address - seg_offset), (long)(seg_length + seg_offset), PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (address != seg_address - seg_offset)
        return -1;

    memcpy((void*)seg_address, elf + p_hdr->p_offset, p_hdr->p_filesz);

    int flags = 0;

    if (p_hdr->p_flags & PF_R)
        flags |= PROT_READ;

    if (p_hdr->p_flags & PF_W)
        flags |= PROT_WRITE;

    if (p_hdr->p_flags & PF_X)
        flags |= PROT_EXEC;

    if (_mprotect((void*)(seg_address - seg_offset), (long)(seg_length + seg_offset), flags) < 0)
        return -1;

    return 0;
}

void elf_loader(struct CLoaderArgs* loader_args) {
    unsigned long eop = 0;

    if (elf_map(loader_args->arg, loader_args->base_address, (unsigned long *)loader_args->auxv, &eop) < 0) {
        LOG("map elf failed");
        return;
    }

    char *av[256] = {};
    char *env[256] = {};

    for (int i = 0; i < loader_args->arg_count; i++) {
        if (i == 0) {
            av[i] = loader_args->arg;
            continue;
        }

        av[i] = av[i-1] + strlen(av[i-1]) + 1;
    }

    for (int i = 0; i < loader_args->env_count; i++) {
        if (i == 0) {
            env[i] = loader_args->arg;
            continue;
        }

        env[i] = env[i-1] + strlen(env[i-1]) + 1;
    }

    unsigned char fake_stack[4096 * 16] = {};
    unsigned char *fake_stack_top = fake_stack + sizeof(fake_stack);

    unsigned char *fake_stack_ptr = make_fake_stack(fake_stack_top, loader_args->arg_count,
                                                    av, env, (unsigned long *)loader_args->auxv);

    if ((unsigned long)fake_stack_ptr % (2 * sizeof(long))) {
        memset(fake_stack, 0, sizeof(fake_stack));
        fake_stack_ptr = make_fake_stack(fake_stack_top - sizeof(long), loader_args->arg_count,
                                         av, env, (unsigned long *)loader_args->auxv);
    }

    LOG("starting");

    asm volatile("xchg %%rsp, %0; jmp *%%rax;" : "=r"(fake_stack_ptr) : "0"(fake_stack_ptr), "a"(eop));
}