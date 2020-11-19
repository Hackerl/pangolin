#include "shellcode.h"
#include <common/log.h>
#include <common/utils/path.h>
#include <cstdio>
#include <sys/mman.h>
#include <elf.h>
#include <string>
#include <cstring>

constexpr unsigned char ELF_MAGIC[] = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3};

constexpr auto SHELLCODE_BEGIN = "shellcode_begin";
constexpr auto SHELLCODE_ENTRY = "shellcode_start";
constexpr auto SHELLCODE_END = "shellcode_end";

CShellcode::CShellcode() {
    mBufferLength = 0;
    mBuffer = nullptr;

    mBegin = 0;
    mEntry = 0;
    mEnd = 0;
}

CShellcode::~CShellcode() {
    close();
}

bool CShellcode::open(const char *filename) {
    std::string path = CPath::join(CPath::getAPPDir(), filename);

    FILE *file = fopen(path.c_str(), "r");

    if (!file) {
        LOG_ERROR("open shellcode '%s' failed", path.c_str());
        return false;
    }

    if (fseek(file, 0, SEEK_END)) {
        fclose(file);
        return false;
    }

    mBufferLength = ftell(file);

    mBuffer = mmap(nullptr, (size_t)mBufferLength, PROT_READ, MAP_PRIVATE,
                   fileno(file), 0);

    fclose(file);

    return mBuffer != nullptr;
}

void CShellcode::close() {
    if (mBuffer) {
        munmap(mBuffer, (size_t)mBufferLength);
        mBuffer = nullptr;
    }
}

bool CShellcode::load() {
    auto elf_hdr = static_cast<Elf64_Ehdr*>(mBuffer);

    if (memcmp(elf_hdr->e_ident, ELF_MAGIC, sizeof(ELF_MAGIC)) != 0) {
        LOG_ERROR("target is not an ELF executable");
        return false;
    }

    if (elf_hdr->e_ident[EI_CLASS] != ELFCLASS64) {
        LOG_ERROR("sorry, only ELF-64 is supported");
        return false;
    }

    if (elf_hdr->e_machine != EM_X86_64) {
        LOG_ERROR("sorry, only x86-64 is supported");
        return false;
    }

    unsigned long baseAddress = 0;

    for (int i = 0; i < elf_hdr->e_phnum; i++) {
        auto offset = elf_hdr->e_phoff + i * elf_hdr->e_phentsize;
        auto pHdr = (Elf64_Phdr *)((unsigned char*)mBuffer + offset);

        if (pHdr->p_type == PT_LOAD) {
            baseAddress = pHdr->p_offset;
            break;
        }
    }

    size_t dynStrOffset = 0;
    size_t dynSymSize = 0;
    size_t dynSymOffset = 0;

    for (uint16_t i = 0; i < elf_hdr->e_shnum; i++) {
        size_t offset = elf_hdr->e_shoff + i * elf_hdr->e_shentsize;
        auto sHdr = (Elf64_Shdr*)((unsigned char*)mBuffer + offset);

        switch (sHdr->sh_type) {
            case SHT_SYMTAB:
            case SHT_STRTAB:
                if (!dynStrOffset) {
                    dynStrOffset = sHdr->sh_offset;
                }

                break;

            case SHT_DYNSYM:
                dynSymSize = sHdr->sh_size;
                dynSymOffset = sHdr->sh_offset;
                break;

            default:
                break;
        }
    }

    for (size_t i = 0; i * sizeof(Elf64_Sym) < dynSymSize; i++) {
        auto absOffset = dynSymOffset + i * sizeof(Elf64_Sym);
        auto sym = (Elf64_Sym*)((unsigned char*)mBuffer + absOffset);

        std::string symName = (char*)mBuffer + dynStrOffset + sym->st_name;

        if (symName == SHELLCODE_BEGIN)
            mBegin = (unsigned long)mBuffer + baseAddress + sym->st_value;
        else if (symName == SHELLCODE_ENTRY)
            mEntry = (unsigned long)mBuffer + baseAddress + sym->st_value;
        else if (symName == SHELLCODE_END)
            mEnd = (unsigned long)mBuffer + baseAddress + sym->st_value;
    }

    return mBegin && mEntry && mEnd;
}

unsigned long CShellcode::getBegin() const {
    return mBegin;
}

unsigned long CShellcode::getEntry() const {
    return mEntry;
}

unsigned long CShellcode::getEnd() const {
    return mEnd;
}
