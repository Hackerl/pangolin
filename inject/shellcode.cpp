#include "shellcode.h"
#include <common/log.h>

constexpr auto PREFIX = "lib";
constexpr auto EXTENSION = "so";

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
                return s->get_name() == ".text";
            });

    if (it == mReader.sections.end()) {
        LOG_ERROR("can't find text section");
        return false;
    }

    unsigned long address = (*it)->get_address();
    unsigned long pageSize = sysconf(_SC_PAGE_SIZE);

    mBuffer = (*it)->get_data();
    mLength = (*it)->get_size();
    mOffset = address & (pageSize - 1);

    return true;
}
