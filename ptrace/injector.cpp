#include "injector.h"
#include "shellcode.h"
#include <cstddef>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <elf.h>
#include <memory>
#include <sys/wait.h>
#include <syscall.h>
#include <common/log.h>
#include <common/utils/process.h>
#include <common/utils/file_walk.h>

#ifdef __i386__

#define REG_PC              eip
#define REG_RET             eax
#define REG_STACK           esp
#define PC_OFFSET           2
#define REG_SYSCALL         orig_eax
#define REG_SYSCALL_ARG     ebx

#elif __x86_64__

#define REG_PC              rip
#define REG_ARG             rdi
#define REG_RET             rax
#define REG_STACK           rsp
#define PC_OFFSET           2
#define REG_SYSCALL         orig_rax
#define REG_SYSCALL_ARG     rdi

#elif __arm__

#include <asm/ptrace.h>

#define REG_PC              uregs[15]
#define REG_ARG             uregs[0]
#define REG_RET             uregs[0]
#define REG_STACK           uregs[13]
#define PC_OFFSET           4
#define REG_SYSCALL         uregs[7]
#define REG_SYSCALL_ARG     uregs[0]

#elif __aarch64__

#define REG_PC              pc
#define REG_ARG             regs[0]
#define REG_RET             regs[0]
#define REG_STACK           sp
#define PC_OFFSET           4
#define REG_SYSCALL         regs[8]
#define REG_SYSCALL_ARG     regs[0]

#else
#error "unknown arch"
#endif

CInjector::CInjector(int pid) {
    mPid = pid;
    mAttached = false;
    mTerminated = false;
}

CInjector::~CInjector() {
    if (mAttached && !mTerminated)
        detach();
}

bool CInjector::attach() {
    for (const auto& t: mThreads){
        if (ptrace(PTRACE_ATTACH, t, nullptr, nullptr) < 0) {
            LOG_ERROR("attach thread %d failed: %s", t, strerror(errno));
            return false;
        }

        int s = 0;

        if (waitpid(t, &s, WUNTRACED) != t) {
            LOG_ERROR("wait pid failed: %s", strerror(errno));
            return false;
        }

        if (WSTOPSIG(s) != SIGSTOP) {
            LOG_ERROR("receive signal: %s", strsignal(WSTOPSIG(s)));
            return false;
        }
    }

    if (!getRegister(mRegister))
        return false;

    LOG_INFO("attach process success");

    mAttached = true;
    return true;
}

bool CInjector::detach() {
    if (!setRegister(mRegister))
        return false;

    for (const auto& t: mThreads){
        if (ptrace(PTRACE_DETACH, t, nullptr, nullptr) < 0) {
            LOG_ERROR("detach thread %d failed: %s", t, strerror(errno));
            continue;
        }
    }

    LOG_INFO("detach process success");

    mAttached = false;
    return true;
}

bool CInjector::run(const char *name, void *base, void *stack, void *arg, int &status) {
    CShellcode shellcode;

    if (!shellcode.load(name)) {
        LOG_ERROR("shellcode load failed");
        return false;
    }

    unsigned long length = shellcode.mOffset + shellcode.mLength;
    std::unique_ptr<unsigned char> memoryBackup(new unsigned char[length]());

    if (!base && !searchExecZone(&base)) {
        LOG_ERROR("search execute zone failed");
        return false;
    }

    LOG_INFO("backup memory: %p[0x%lx]", base, length);

    if (!readMemory(base, memoryBackup.get(), length))
        return false;

    LOG_INFO("jump entry: %p[0x%lx]", base, shellcode.mOffset);

    if (!writeMemory((char *)base + shellcode.mOffset, (void *)shellcode.mBuffer, shellcode.mLength))
        return false;

    CRegister modifyRegs = mRegister;

    modifyRegs.REG_PC = (unsigned long)base + PC_OFFSET + shellcode.mOffset;
    modifyRegs.REG_STACK = stack ? (unsigned long)stack : mRegister.REG_STACK;

#ifdef __i386__
    if (!writeMemory((char *)modifyRegs.REG_STACK - sizeof(arg), &arg, sizeof(arg)))
        return false;

    modifyRegs.REG_STACK -= sizeof(arg);
#else
    modifyRegs.REG_ARG = (unsigned long)arg;
#endif

    if (!setRegister(modifyRegs))
        return false;

    int sig = 0;

    while (true) {
        if (ptrace(PTRACE_SYSCALL, mPid, nullptr, sig) < 0) {
            LOG_ERROR("ptrace syscall failed: %s", strerror(errno));
            return false;
        }

        int s = 0;

        if (waitpid(mPid, &s, 0) < 0) {
            LOG_ERROR("wait pid failed: %s", strerror(errno));
            return false;
        }

        if (WIFSIGNALED(s)) {
            LOG_WARNING("process terminated: %s", strsignal(WTERMSIG(s)));
            mTerminated = true;
            return false;
        }

        CRegister currentRegs = {};

        if (!getRegister(currentRegs))
            return false;

        sig = WSTOPSIG(s);

        if (sig == SIGSEGV) {
            LOG_ERROR("segmentation fault: 0x%lx", currentRegs.REG_PC);
            break;
        }

        if (sig != SIGTRAP) {
            LOG_INFO("receive signal: %s", strsignal(sig));
            continue;
        }

        sig = 0;

        if (currentRegs.REG_SYSCALL == SYS_exit || currentRegs.REG_SYSCALL == SYS_exit_group) {
            cancelSyscall();
            status = (int)currentRegs.REG_SYSCALL_ARG;

            LOG_INFO("exit status: %d", status);
            break;
        }
    }

    LOG_INFO("restore memory");

    if (!writeMemory(base, memoryBackup.get(), length))
        return false;

    return sig != SIGSEGV;
}

bool CInjector::call(const char *name, void *base, void *stack, void *arg, void **result) {
    CShellcode shellcode;

    if (!shellcode.load(name)) {
        LOG_ERROR("shellcode load failed");
        return false;
    }

    unsigned long length = shellcode.mOffset + shellcode.mLength;
    std::unique_ptr<unsigned char> memoryBackup(new unsigned char[length]());

    if (!base && !searchExecZone(&base)) {
        LOG_ERROR("search execute zone failed");
        return false;
    }

    LOG_INFO("backup memory: %p[0x%lx]", base, length);

    if (!readMemory(base, memoryBackup.get(), length))
        return false;

    LOG_INFO("jump entry: %p[0x%lx]", base, shellcode.mOffset);

    if (!writeMemory((char *)base + shellcode.mOffset, (void *)shellcode.mBuffer, shellcode.mLength))
        return false;

    CRegister modifyRegs = mRegister;

    modifyRegs.REG_PC = (unsigned long)base + PC_OFFSET + shellcode.mOffset;
    modifyRegs.REG_STACK = stack ? (unsigned long)stack : mRegister.REG_STACK;

#ifdef __i386__
    if (!writeMemory((char *)modifyRegs.REG_STACK - sizeof(arg), &arg, sizeof(arg)))
        return false;

    modifyRegs.REG_STACK -= sizeof(arg);
#else
    modifyRegs.REG_ARG = (unsigned long)arg;
#endif

    if (!setRegister(modifyRegs))
        return false;

    int sig = 0;

    while (true) {
        if (ptrace(PTRACE_CONT, mPid, nullptr, sig) < 0) {
            LOG_ERROR("ptrace continue failed: %s", strerror(errno));
            return false;
        }

        int s = 0;

        if (waitpid(mPid, &s, 0) < 0) {
            LOG_ERROR("wait pid failed: %s", strerror(errno));
            return false;
        }

        if (WIFSIGNALED(s)) {
            LOG_WARNING("process terminated: %s", strsignal(WTERMSIG(s)));
            mTerminated = true;
            return false;
        }

        CRegister currentRegs = {};

        if (!getRegister(currentRegs))
            return false;

        sig = WSTOPSIG(s);

        if (sig == SIGSEGV) {
            LOG_ERROR("segmentation fault: 0x%lx", currentRegs.REG_PC);
            break;
        }

        if (sig == SIGTRAP) {
            if (result)
                *result = (void *)currentRegs.REG_RET;

            break;
        }

        LOG_INFO("receive signal: %s", strsignal(sig));
    }

    LOG_INFO("restore memory");

    if (!writeMemory(base, memoryBackup.get(), length))
        return false;

    return sig != SIGSEGV;
}

bool CInjector::getRegister(CRegister &regs) const {
    iovec io = {};

    io.iov_base = &regs;
    io.iov_len = sizeof(CRegister);

    if (ptrace(PTRACE_GETREGSET, mPid, (void *)NT_PRSTATUS, (void *)&io) < 0) {
        LOG_ERROR("get register failed: %s", strerror(errno));
        return false;
    }

    return true;
}

bool CInjector::setRegister(CRegister regs) const {
    iovec io = {};

    io.iov_base = &regs;
    io.iov_len = sizeof(CRegister);

    if (ptrace(PTRACE_SETREGSET, mPid, (void *)NT_PRSTATUS, (void *)&io) < 0) {
        LOG_ERROR("set register failed: %s", strerror(errno));
        return false;
    }

    return true;
}

bool CInjector::readMemory(void *address, void *buffer, unsigned long length) const {
    if (length < sizeof(long)) {
        LOG_ERROR("buffer length need greater than size of long");
        return false;
    }

    for (unsigned long i = 0; i < length; i += sizeof(long)) {
        if (length - i < sizeof(long)) {
            i = length - sizeof(long);
        }

        long r = ptrace(PTRACE_PEEKTEXT, mPid, (unsigned char *)address + i, nullptr);

        if (r == -1 && errno != 0) {
            LOG_ERROR("read memory failed: %s", strerror(errno));
            return false;
        }

        *(long *)((unsigned char *)buffer + i) = r;
    }

    return true;
}

bool CInjector::writeMemory(void *address, void *buffer, unsigned long length) const {
    if (length < sizeof(long)) {
        LOG_ERROR("buffer length need greater than size of long");
        return false;
    }

    for (unsigned long i = 0; i < length; i += sizeof(long)) {
        if (length - i < sizeof(long)) {
            i = length - sizeof(long);
        }

        if (ptrace(PTRACE_POKETEXT, mPid, (unsigned char *)address + i, *(long *)((unsigned char *)buffer + i)) < 0) {
            LOG_ERROR("write memory failed: %s", strerror(errno));
            return false;
        }
    }

    return true;
}

bool CInjector::cancelSyscall() const {
#ifdef __arm__
    if (ptrace((__ptrace_request)PTRACE_SET_SYSCALL, mPid, nullptr, (void *)-1) < 0) {
        LOG_ERROR("cancel syscall failed: %s", strerror(errno));
        return false;
    }

#elif __aarch64__
    long sysNR = -1;

    iovec iov = {};

    iov.iov_base = &sysNR;
    iov.iov_len = sizeof(long);

    if (ptrace(PTRACE_SETREGSET, mPid, (void *)NT_ARM_SYSTEM_CALL, &iov) < 0) {
        LOG_ERROR("cancel syscall failed: %s", strerror(errno));
        return false;
    }

#else
    if (ptrace(PTRACE_POKEUSER, mPid, offsetof(CRegister, REG_SYSCALL), (void *)-1) < 0) {
        LOG_ERROR("cancel syscall failed: %s", strerror(errno));
        return false;
    }
#endif

    return true;
}

bool CInjector::searchExecZone(void **base) const {
    std::list<CProcessMap> processMaps;

    if (!CProcess::getProcessMaps(mPid, processMaps)) {
        LOG_ERROR("get process maps failed");
        return false;
    }

    auto it = std::find_if(
            processMaps.begin(),
            processMaps.end(),
            [](const auto& m) {
                return m.permissions == "r-xp" || m.permissions == "rwxp";
            });

    if (it == processMaps.end())
        return false;

    *base = (void *)(*it).start;

    return true;
}

bool CInjector::init() {
    std::string path = CPath::join("/proc", std::to_string(mPid), "task");

    for (const auto &i : CFileWalker(path)) {
        int thread = 0;

        if (!CStringHelper::toNumber(i.filename, thread)) {
            LOG_ERROR("parse thread id failed: %s", i.filename.c_str());
            return false;
        }

        mThreads.emplace_back(thread);
    }

    return true;
}