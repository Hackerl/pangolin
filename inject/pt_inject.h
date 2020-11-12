#ifndef PANGOLIN_PT_INJECT_H
#define PANGOLIN_PT_INJECT_H

#include <sys/user.h>
#include <common/utils/process.h>

class CPTInject {
public:
    explicit CPTInject(int pid);
    ~CPTInject();

public:
    bool attach();
    bool detach();

public:
    bool runCode(void *buffer, unsigned long length,
                 unsigned long offset, void *base, void *arg) const;

    bool callCode(void *buffer, unsigned long length,
                  unsigned long offset, void *base, void *arg, void **result) const;

private:
    bool searchExecZone(void **base) const;

public:
    bool getRegister(user_regs_struct& regs) const;
    bool setRegister(user_regs_struct regs) const;

public:
    bool readMemory(void *address, void *buffer, unsigned long length) const;
    bool writeMemory(void *address, void *buffer, unsigned long length) const;

private:
    bool cancelSyscall() const;

public:
    int mPid;
    bool mAttached;
    user_regs_struct mRegister{};
};


#endif //PANGOLIN_PT_INJECT_H
