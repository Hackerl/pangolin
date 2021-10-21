#include "tracee.h"
#include <sys/ptrace.h>
#include <cerrno>
#include <cstring>
#include <zero/log.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <elf.h>

CTracee::CTracee(pid_t pid) {
    mPID = pid;
}

bool CTracee::attach() const {
    if (ptrace(PTRACE_ATTACH, mPID, nullptr, nullptr) < 0) {
        LOG_ERROR("attach process %d failed: %s", mPID, strerror(errno));
        return false;
    }

    int s = 0;

    if (waitpid(mPID, &s, WUNTRACED) != mPID) {
        LOG_ERROR("wait process %d failed: %s", mPID, strerror(errno));
        return false;
    }

    if (WSTOPSIG(s) != SIGSTOP) {
        LOG_ERROR("receive signal: %s", strsignal(WSTOPSIG(s)));
        return false;
    }

    return true;
}

bool CTracee::detach() const {
    if (ptrace(PTRACE_DETACH, mPID, nullptr, nullptr) < 0) {
        LOG_ERROR("detach process %d failed: %s", mPID, strerror(errno));
        return false;
    }

    return true;
}

bool CTracee::getRegisters(regs_t &regs) const {
    iovec io = {};

    io.iov_base = &regs;
    io.iov_len = sizeof(regs_t);

    if (ptrace(PTRACE_GETREGSET, mPID, (void *)NT_PRSTATUS, (void *)&io) < 0) {
        LOG_ERROR("get process %d registers failed: %s", mPID, strerror(errno));
        return false;
    }

    return true;
}

bool CTracee::setRegisters(regs_t &regs) const {
    iovec io = {};

    io.iov_base = &regs;
    io.iov_len = sizeof(regs_t);

    if (ptrace(PTRACE_SETREGSET, mPID, (void *)NT_PRSTATUS, (void *)&io) < 0) {
        LOG_ERROR("set process %d registers failed: %s", mPID, strerror(errno));
        return false;
    }

    return true;
}

bool CTracee::readMemory(void *address, void *buffer, unsigned long length) const {
    for (unsigned long i = 0; i < length; i += sizeof(long)) {
        long r = ptrace(PTRACE_PEEKTEXT, mPID, (char *)address + i, nullptr);

        if (r == -1 && errno != 0) {
            LOG_ERROR("read process %d memory failed: %s", mPID, strerror(errno));
            return false;
        }

        memcpy((char *)buffer + i, &r, std::min(length - i, sizeof(long)));
    }

    return true;
}

bool CTracee::writeMemory(void *address, void *buffer, unsigned long length) const {
    if (length < sizeof(long)) {
        LOG_ERROR("buffer length need greater than size of long");
        return false;
    }

    for (unsigned long i = 0; i < length; i += sizeof(long)) {
        if (length - i < sizeof(long)) {
            i = length - sizeof(long);
        }

        if (ptrace(PTRACE_POKETEXT, mPID, (char *)address + i, *(long *)((char *)buffer + i)) < 0) {
            LOG_ERROR("write process %d memory failed: %s", mPID, strerror(errno));
            return false;
        }
    }

    return true;
}

bool CTracee::resume(int sig) const {
    if (ptrace(PTRACE_CONT, mPID, nullptr, sig) < 0) {
        LOG_ERROR("continue process %d failed: %s", mPID, strerror(errno));
        return false;
    }

    return true;
}

bool CTracee::catchSyscall(int sig) const {
    if (ptrace(PTRACE_SYSCALL, mPID, nullptr, sig) < 0) {
        LOG_ERROR("catch process %d syscall failed: %s", mPID, strerror(errno));
        return false;
    }

    return true;
}

bool CTracee::setSyscall(long number) const {
#ifdef __arm__
    if (ptrace((__ptrace_request)PTRACE_SET_SYSCALL, mPID, nullptr, (void *)number) < 0) {
        LOG_ERROR("set process %d syscall failed: %s", mPID, strerror(errno));
        return false;
    }

#elif __aarch64__
    iovec iov = {};

    iov.iov_base = &number;
    iov.iov_len = sizeof(long);

    if (ptrace(PTRACE_SETREGSET, mPID, (void *)NT_ARM_SYSTEM_CALL, &iov) < 0) {
        LOG_ERROR("set process %d syscall failed: %s", mPID, strerror(errno));
        return false;
    }

#elif __i386__
    if (ptrace(PTRACE_POKEUSER, mPID, offsetof(regs_t, orig_eax), (void *)number) < 0) {
        LOG_ERROR("set process %d syscall failed: %s", mPID, strerror(errno));
        return false;
    }

#elif __x86_64__
    if (ptrace(PTRACE_POKEUSER, mPID, offsetof(regs_t, orig_rax), (void *)number) < 0) {
        LOG_ERROR("set process %d catchSyscall failed: %s", mPID, strerror(errno));
        return false;
    }
#endif

    return true;
}
