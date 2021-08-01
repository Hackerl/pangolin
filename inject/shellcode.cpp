#include "shellcode.h"
#include <common/log.h>

constexpr auto PREFIX = "lib";
constexpr auto EXTENSION = "so";

constexpr auto SHELLCODE_ENTRY = "shellcode_start";

bool CShellcode::load(const std::string &shellcode) {
    std::string filename = CStringHelper::format("%s%s.%s", PREFIX, shellcode.c_str(), EXTENSION);
    std::string path = CPath::join(CPath::getAPPDir(), filename);

    if (!mReader.load(path)) {
        LOG_ERROR("open shellcode failed: %s", shellcode.c_str());
        return false;
    }

    auto it = std::find_if(
            mReader.sections.begin(),
            mReader.sections.end(),
            [](const auto& s) {
                return s->get_type() == SHT_DYNSYM;
            });

    if (it == mReader.sections.end()) {
        LOG_ERROR("can't find symbol section");
        return false;
    }

    ELFIO::Elf64_Addr entry = -1;
    ELFIO::symbol_section_accessor symbols(mReader, *it);

    for (ELFIO::Elf_Xword i = 0; i < symbols.get_symbols_num(); i++) {
        std::string name;
        ELFIO::Elf64_Addr value = 0;
        ELFIO::Elf_Xword size = 0;
        unsigned char bind = 0;
        unsigned char type = 0;
        ELFIO::Elf_Half section = 0;
        unsigned char other = 0;

        if (!symbols.get_symbol(i, name, value, size, bind, type, section, other)) {
            LOG_ERROR("get symbol %lu failed", i);
            return false;
        }

        if (name == SHELLCODE_ENTRY) {
            entry = value;
            break;
        }
    }

    if (entry == -1) {
        LOG_ERROR("can't find shellcode symbols");
        return false;
    }

    auto sit = std::find_if(
            mReader.sections.begin(),
            mReader.sections.end(),
            [](const auto& s) {
                return s->get_name() == ".text";
            });

    if (sit == mReader.sections.end()) {
        LOG_ERROR("can't find text section");
        return false;
    }

    unsigned long address = (*sit)->get_address();
    unsigned long pageSize = sysconf(_SC_PAGE_SIZE);

    mBuffer = (*sit)->get_data();
    mLength = (*sit)->get_size();
    mAlign = address & (pageSize - 1);
    mEntry = entry - address;

    return true;
}
