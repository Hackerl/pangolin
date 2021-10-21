#ifndef PANGOLIN_TRACEE_H
#define PANGOLIN_TRACEE_H

#include <set>
#include <sys/user.h>
#include <sys/types.h>

#ifdef __arm__
typedef user_regs regs_t;
#else
typedef user_regs_struct regs_t;
#endif

class CTracee {
public:
    explicit CTracee(pid_t pid);

public:
    bool attach() const;
    bool detach() const;

public:
    bool resume(int sig) const;
    bool catchSyscall(int sig) const;

public:
    bool getRegisters(regs_t &regs) const;
    bool setRegisters(regs_t &regs) const;

public:
    bool readMemory(void *address, void *buffer, unsigned long length) const;
    bool writeMemory(void *address, void *buffer, unsigned long length) const;

public:
    bool setSyscall(long number) const;

protected:
    pid_t mPID;
};


#endif //PANGOLIN_TRACEE_H
