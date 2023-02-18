#include "tracee.h"
#include <cstddef>
#include <sys/ptrace.h>
#include <zero/log.h>
#include <cerrno>
#include <sys/wait.h>
#include <sys/uio.h>
#include <elf.h>

#ifdef __arm__
#include <asm/ptrace.h>
#endif

Tracee::Tracee(pid_t pid) : mPID(pid), mAttached(false) {

}

Tracee::~Tracee() {
    if (!mAttached)
        return;

    std::ignore = detach();
}

bool Tracee::attach() {
    if (ptrace(PTRACE_ATTACH, mPID, nullptr, nullptr) < 0) {
        LOG_ERROR("attach process %d failed: %s", mPID, strerror(errno));
        return false;
    }

    int s = 0;

    if (waitpid(mPID, &s, __WALL | WUNTRACED) != mPID) {
        LOG_ERROR("wait process %d failed: %s", mPID, strerror(errno));
        return false;
    }

    if (WSTOPSIG(s) != SIGSTOP) {
        LOG_ERROR("receive signal: %s", strsignal(WSTOPSIG(s)));
        return false;
    }

    mAttached = true;
    return true;
}

bool Tracee::detach() {
    if (ptrace(PTRACE_DETACH, mPID, nullptr, nullptr) < 0) {
        LOG_ERROR("detach process %d failed: %s", mPID, strerror(errno));
        return false;
    }

    mAttached = false;
    return true;
}

std::optional<regs_t> Tracee::getRegisters() const {
    regs_t regs = {};

    iovec io = {
            &regs,
            sizeof(regs_t)
    };

    if (ptrace(PTRACE_GETREGSET, mPID, (void *) NT_PRSTATUS, (void *) &io) < 0) {
        LOG_ERROR("get process %d registers failed: %s", mPID, strerror(errno));
        return std::nullopt;
    }

    return regs;
}

bool Tracee::setRegisters(const regs_t &regs) const {
    iovec io = {
            (void *) &regs,
            sizeof(regs_t)
    };

    if (ptrace(PTRACE_SETREGSET, mPID, (void *) NT_PRSTATUS, (void *) &io) < 0) {
        LOG_ERROR("set process %d registers failed: %s", mPID, strerror(errno));
        return false;
    }

    return true;
}

std::optional<fp_regs_t> Tracee::getFPRegisters() const {
    fp_regs_t fp_regs = {};

    iovec io = {
            &fp_regs,
            sizeof(fp_regs_t)
    };

    if (ptrace(PTRACE_GETREGSET, mPID, (void *) NT_FPREGSET, (void *) &io) < 0) {
        LOG_ERROR("get process %d fp-registers failed: %s", mPID, strerror(errno));
        return std::nullopt;
    }

    return fp_regs;
}

bool Tracee::setFPRegisters(const fp_regs_t &fp_regs) const {
    iovec io = {
            (void *) &fp_regs,
            sizeof(fp_regs_t)
    };

    if (ptrace(PTRACE_SETREGSET, mPID, (void *) NT_FPREGSET, (void *) &io) < 0) {
        LOG_ERROR("set process %d fp-registers failed: %s", mPID, strerror(errno));
        return false;
    }

    return true;
}

#if __arm__ || __aarch64__
std::optional<uintptr_t> Tracee::getTLS() const {
    uintptr_t tls = 0;

    iovec io = {
            &tls,
            sizeof(uintptr_t)
    };

    if (ptrace(PTRACE_GETREGSET, mPID, (void *) NT_ARM_TLS, (void *) &io) < 0) {
        LOG_ERROR("get process %d tls failed: %s", mPID, strerror(errno));
        return std::nullopt;
    }

    return tls;
}

bool Tracee::setTLS(uintptr_t tls) const {
    iovec io = {
            &tls,
            sizeof(uintptr_t)
    };

    if (ptrace(PTRACE_SETREGSET, mPID, (void *) NT_ARM_TLS, (void *) &io) < 0) {
        LOG_ERROR("set process %d tls failed: %s", mPID, strerror(errno));
        return false;
    }

    return true;
}
#endif

bool Tracee::readMemory(uintptr_t address, void *buffer, size_t length) const {
    for (size_t i = 0; i < length; i += sizeof(long)) {
        long r = ptrace(PTRACE_PEEKTEXT, mPID, address + i, nullptr);

        if (r == -1 && errno != 0) {
            LOG_ERROR("read process %d memory failed: %s", mPID, strerror(errno));
            return false;
        }

        memcpy((char *) buffer + i, &r, std::min(length - i, sizeof(long)));
    }

    return true;
}

bool Tracee::writeMemory(uintptr_t address, void *buffer, size_t length) const {
    if (length < sizeof(long)) {
        LOG_ERROR("buffer length need greater than size of long");
        return false;
    }

    for (size_t i = 0; i < length; i += sizeof(long)) {
        if (length - i < sizeof(long)) {
            i = length - sizeof(long);
        }

        if (ptrace(PTRACE_POKETEXT, mPID, address + i, *(long *) ((char *) buffer + i)) < 0) {
            LOG_ERROR("write process %d memory failed: %s", mPID, strerror(errno));
            return false;
        }
    }

    return true;
}

bool Tracee::resume(int sig) const {
    if (ptrace(PTRACE_CONT, mPID, nullptr, sig) < 0) {
        LOG_ERROR("resume process %d failed: %s", mPID, strerror(errno));
        return false;
    }

    return true;
}

bool Tracee::catchSyscall(int sig) const {
    if (ptrace(PTRACE_SYSCALL, mPID, nullptr, sig) < 0) {
        LOG_ERROR("catch process %d syscall failed: %s", mPID, strerror(errno));
        return false;
    }

    return true;
}

bool Tracee::setSyscall(long number) const {
#ifdef __arm__
    if (ptrace((__ptrace_request) PTRACE_SET_SYSCALL, mPID, nullptr, (void *) number) < 0) {
        LOG_ERROR("set process %d syscall failed: %s", mPID, strerror(errno));
        return false;
    }

#elif __aarch64__
    iovec iov = {
            &number,
            sizeof(long)
    };

    if (ptrace(PTRACE_SETREGSET, mPID, (void *) NT_ARM_SYSTEM_CALL, &iov) < 0) {
        LOG_ERROR("set process %d syscall failed: %s", mPID, strerror(errno));
        return false;
    }

#elif __i386__
    if (ptrace(PTRACE_POKEUSER, mPID, offsetof(regs_t, orig_eax), (void *) number) < 0) {
        LOG_ERROR("set process %d syscall failed: %s", mPID, strerror(errno));
        return false;
    }

#elif __x86_64__
    if (ptrace(PTRACE_POKEUSER, mPID, offsetof(regs_t, orig_rax), (void *) number) < 0) {
        LOG_ERROR("set process %d syscall failed: %s", mPID, strerror(errno));
        return false;
    }
#endif

    return true;
}
