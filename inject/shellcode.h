#ifndef PANGOLIN_SHELLCODE_H
#define PANGOLIN_SHELLCODE_H

#include <string>
#include <elfio/elfio.hpp>

class CShellcode {
public:
    bool load(const std::string& filename);

public:
    const char *mBegin;
    const char *mEntry;
    const char *mEnd;

private:
    ELFIO::elfio mReader;
};


#endif //PANGOLIN_SHELLCODE_H
