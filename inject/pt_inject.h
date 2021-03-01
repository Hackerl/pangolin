#ifndef PANGOLIN_PT_INJECT_H
#define PANGOLIN_PT_INJECT_H

#include <list>
#include <sys/user.h>

class CPTInject {
public:
    explicit CPTInject(int pid);
    ~CPTInject();

public:
    bool init();

public:
    bool attach();
    bool detach();

public:
    bool runCode(const char *name, void *base, void *arg, int &status) const;
    bool callCode(const char *name, void *base, void *arg, void **result) const;

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
    std::list<int> mThreads;
    user_regs_struct mRegister{};
};


#endif //PANGOLIN_PT_INJECT_H
