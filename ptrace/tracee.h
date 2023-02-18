#ifndef PANGOLIN_TRACEE_H
#define PANGOLIN_TRACEE_H

#include <sys/user.h>
#include <sys/types.h>
#include <cstdint>
#include <optional>

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

class Tracee {
public:
    explicit Tracee(pid_t pid);
    ~Tracee();

public:
    bool attach();
    bool detach();

public:
    [[nodiscard]] bool resume(int sig) const;
    [[nodiscard]] bool catchSyscall(int sig) const;

public:
    [[nodiscard]] std::optional<regs_t> getRegisters() const;
    [[nodiscard]] bool setRegisters(const regs_t &regs) const;

public:
    [[nodiscard]] std::optional<fp_regs_t> getFPRegisters() const;
    [[nodiscard]] bool setFPRegisters(const fp_regs_t &fp_regs) const;

#if __arm__ || __aarch64__
public:
    [[nodiscard]] std::optional<uintptr_t> getTLS() const;
    [[nodiscard]] bool setTLS(uintptr_t tls) const;
#endif

public:
    [[nodiscard]] bool readMemory(uintptr_t address, void *buffer, size_t length) const;
    [[nodiscard]] bool writeMemory(uintptr_t address, void *buffer, size_t length) const;

public:
    [[nodiscard]] bool setSyscall(long number) const;

protected:
    pid_t mPID;
    bool mAttached;
};


#endif //PANGOLIN_TRACEE_H
