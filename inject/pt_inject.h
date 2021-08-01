#ifndef PANGOLIN_PT_INJECT_H
#define PANGOLIN_PT_INJECT_H

#include <list>
#include <sys/user.h>

#ifdef __arm__
typedef user_regs CRegister;
#else
typedef user_regs_struct CRegister;
#endif

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
    bool run(const char *name, void *base, void *stack, void *arg, int &status) const;
    bool call(const char *name, void *base, void *stack, void *arg, void **result) const;

private:
    bool searchExecZone(void **base) const;

public:
    bool getRegister(CRegister& regs) const;
    bool setRegister(CRegister regs) const;

public:
    bool readMemory(void *address, void *buffer, unsigned long length) const;
    bool writeMemory(void *address, void *buffer, unsigned long length) const;

private:
    bool cancelSyscall() const;

private:
    int mPid;
    bool mAttached;
    std::list<int> mThreads;

private:
    CRegister mRegister{};
};


#endif //PANGOLIN_PT_INJECT_H
