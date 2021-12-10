#ifndef PANGOLIN_TRACEE_H
#define PANGOLIN_TRACEE_H

#include <set>
#include <sys/user.h>
#include <sys/types.h>

#if __arm__ || __aarch64__
#include <cstdint>
#endif

#ifdef __arm__
typedef user_regs regs_t;
typedef user_fpregs fp_regs_t;
#elif __aarch64__
typedef user_regs_struct regs_t;
typedef user_fpsimd_struct fp_regs_t;
#else
typedef user_regs_struct regs_t;
typedef user_fpregs_struct fp_regs_t;
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
    bool getFPRegisters(fp_regs_t &fp_regs) const;
    bool setFPRegisters(fp_regs_t &fp_regs) const;

#if __arm__ || __aarch64__
public:
    bool getTLS(uintptr_t &tls) const;
    bool setTLS(uintptr_t &tls) const;
#endif

public:
    bool readMemory(void *address, void *buffer, unsigned long length) const;
    bool writeMemory(void *address, void *buffer, unsigned long length) const;

public:
    bool setSyscall(long number) const;

protected:
    pid_t mPID;
};


#endif //PANGOLIN_TRACEE_H
