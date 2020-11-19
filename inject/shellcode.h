#ifndef PANGOLIN_SHELLCODE_H
#define PANGOLIN_SHELLCODE_H

class CShellcode {
public:
    CShellcode();
    ~CShellcode();

public:
    bool open(const char *filename);
    bool load();
    void close();

public:
    unsigned long getBegin() const;
    unsigned long getEntry() const;
    unsigned long getEnd() const;

private:
    void *mBuffer;
    long mBufferLength;
    unsigned long mBegin;
    unsigned long mEntry;
    unsigned long mEnd;
};


#endif //PANGOLIN_SHELLCODE_H
