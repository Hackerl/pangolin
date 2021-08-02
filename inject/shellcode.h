#ifndef PANGOLIN_SHELLCODE_H
#define PANGOLIN_SHELLCODE_H

#include <string>
#include <elfio/elfio.hpp>

class CShellcode {
public:
    bool load(const std::string& shellcode);

public:
    const char *mBuffer;

public:
    unsigned long mOffset;
    unsigned long mEntry;
    unsigned long mLength;

private:
    ELFIO::elfio mReader;
};


#endif //PANGOLIN_SHELLCODE_H
