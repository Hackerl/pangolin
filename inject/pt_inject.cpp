#include "pt_inject.h"
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

CPTInject::CPTInject(int pid) {
    mPid = pid;
    mAttached = false;
}

CPTInject::~CPTInject() {
    if (mAttached)
        detach();
}

bool CPTInject::attach() {
    for (const auto& t: mThreads){
        if (ptrace(PTRACE_ATTACH, t, nullptr, nullptr) < 0) {
            LOG_ERROR("attach thread failed: %d", t);
            return false;
        }

        int s = 0;

        if (waitpid(t, &s, WUNTRACED) != t) {
            LOG_ERROR("wait pid failed: %d",  t);
            return false;
        }

        if (WSTOPSIG(s) != SIGSTOP) {
            LOG_ERROR("attach receive signal: %s", strsignal(WSTOPSIG(s)));
            return false;
        }
    }

    if (!getRegister(mRegister))
        return false;

    LOG_INFO("attach process success");

    mAttached = true;
    return true;
}

bool CPTInject::detach() {
    if (!setRegister(mRegister))
        return false;

    for (const auto& t: mThreads){
        if (ptrace(PTRACE_DETACH, t, nullptr, nullptr) < 0) {
            LOG_ERROR("detach thread failed: %d", t);
            continue;
        }
    }

    LOG_INFO("detach process success");

    mAttached = false;
    return true;
}

bool CPTInject::run(const char *name, void *base, void *stack, void *arg, int &status) const {
    CShellcode shellcode;

    if (!shellcode.load(name)) {
        LOG_ERROR("shellcode load failed");
        return false;
    }

    unsigned long offset = shellcode.mAlign + shellcode.mEntry;
    unsigned long length = shellcode.mAlign + shellcode.mLength;

    void *memoryBase = base;
    std::unique_ptr<unsigned char> memoryBackup(new unsigned char[length]());

    if (!memoryBase && !searchExecZone(&memoryBase)) {
        LOG_ERROR("search execute zone failed");
        return false;
    }

    LOG_INFO("backup memory");

    if (!readMemory(memoryBase, memoryBackup.get(), length))
        return false;

    LOG_INFO("inject code at: %p entry: 0x%lx size: 0x%lx", memoryBase, offset, length);

    if (!writeMemory((char *)memoryBase + shellcode.mAlign, (void *)shellcode.mBuffer, shellcode.mLength))
        return false;

    CRegister modifyRegs = mRegister;

    modifyRegs.REG_PC = (unsigned long long)memoryBase + PC_OFFSET + offset;
    modifyRegs.REG_STACK = stack ? (unsigned long long)stack : mRegister.REG_STACK;

#ifdef __i386__
    if (!writeMemory(modifyRegs.REG_STACK - sizeof(arg), &arg, sizeof(arg)))
        return false;

    modifyRegs.REG_STACK -= sizeof(arg);
#else
    modifyRegs.REG_ARG = (unsigned long long)arg;
#endif

    if (!setRegister(modifyRegs))
        return false;

    int sig = 0;

    while (true) {
        if (ptrace(PTRACE_SYSCALL, mPid, nullptr, sig) < 0) {
            LOG_ERROR("trace syscall failed");
            return false;
        }

        int s = 0;

        if (waitpid(mPid, &s, 0) < 0 || WIFEXITED(s)) {
            LOG_ERROR("wait pid failed");
            return false;
        }

        CRegister currentRegs = {};

        if (!getRegister(currentRegs))
            return false;

        sig = WSTOPSIG(s);

        if (sig == SIGSEGV) {
            LOG_ERROR("segmentation fault: 0x%llx", currentRegs.REG_PC);
            break;
        }

        if (sig != SIGTRAP) {
            LOG_INFO("receive signal: %s", strsignal(sig));
            continue;
        }

        sig = 0;

        if (currentRegs.REG_SYSCALL == -1) {
            LOG_INFO("exit status: %d", status);
            break;
        }

        if (currentRegs.REG_SYSCALL == SYS_exit || currentRegs.REG_SYSCALL == SYS_exit_group) {
            status = (int)currentRegs.REG_SYSCALL_ARG;
            cancelSyscall();

#ifdef __aarch64__
            LOG_INFO("exit status: %d", status);
            break;
#endif
        }
    }

    LOG_INFO("restore memory");

    if (!writeMemory(memoryBase, memoryBackup.get(), length))
        return false;

    return sig != SIGSEGV;
}

bool CPTInject::call(const char *name, void *base, void *stack, void *arg, void **result) const {
    CShellcode shellcode;

    if (!shellcode.load(name)) {
        LOG_ERROR("shellcode load failed");
        return false;
    }

    unsigned long offset = shellcode.mAlign + shellcode.mEntry;
    unsigned long length = shellcode.mAlign + shellcode.mLength;

    void *memoryBase = base;
    std::unique_ptr<unsigned char> memoryBackup(new unsigned char[length]());

    if (!memoryBase && !searchExecZone(&memoryBase)) {
        LOG_ERROR("search execute zone failed");
        return false;
    }

    LOG_INFO("backup memory");

    if (!readMemory(memoryBase, memoryBackup.get(), length))
        return false;

    LOG_INFO("inject code at: %p entry: 0x%lx size: 0x%lx", memoryBase, offset, length);

    if (!writeMemory((char *)memoryBase + shellcode.mAlign, (void *)shellcode.mBuffer, shellcode.mLength))
        return false;

    CRegister modifyRegs = mRegister;

    modifyRegs.REG_PC = (unsigned long long)memoryBase + PC_OFFSET + offset;
    modifyRegs.REG_STACK = stack ? (unsigned long long)stack : mRegister.REG_STACK;

#ifdef __i386__
    if (!writeMemory(modifyRegs.REG_STACK - sizeof(arg), &arg, sizeof(arg)))
        return false;

    modifyRegs.REG_STACK -= sizeof(arg);
#else
    modifyRegs.REG_ARG = (unsigned long long)arg;
#endif

    if (!setRegister(modifyRegs))
        return false;

    int sig = 0;

    while (true) {
        if (ptrace(PTRACE_CONT, mPid, nullptr, sig) < 0) {
            LOG_ERROR("trace continue failed");
            return false;
        }

        int s = 0;

        if (waitpid(mPid, &s, 0) < 0 || WIFEXITED(s)) {
            LOG_ERROR("wait pid failed");
            return false;
        }

        sig = WSTOPSIG(s);

        if (sig == SIGTRAP || sig == SIGSEGV)
            break;

        LOG_INFO("receive signal: %s", strsignal(sig));
    }

    LOG_INFO("restore memory");

    if (!writeMemory(memoryBase, memoryBackup.get(), length))
        return false;

    CRegister currentRegs = {};

    if (!getRegister(currentRegs))
        return false;

    if (sig == SIGSEGV) {
        LOG_ERROR("segmentation fault: 0x%llx", currentRegs.REG_PC);
        return false;
    }

    if (result)
        *result = (void *)currentRegs.REG_RET;

    return true;
}

bool CPTInject::getRegister(CRegister &regs) const {
    iovec io = {};

    io.iov_base = &regs;
    io.iov_len = sizeof(CRegister);

    if (ptrace(PTRACE_GETREGSET, mPid, (void*)NT_PRSTATUS, (void*)&io) < 0) {
        LOG_ERROR("get register failed: %s", strerror(errno));
        return false;
    }

    return true;
}

bool CPTInject::setRegister(CRegister regs) const {
    iovec io = {};

    io.iov_base = &regs;
    io.iov_len = sizeof(CRegister);

    if (ptrace(PTRACE_SETREGSET, mPid, (void*)NT_PRSTATUS, (void*)&io) < 0) {
        LOG_ERROR("set register failed");
        return false;
    }

    return true;
}

bool CPTInject::readMemory(void *address, void *buffer, unsigned long length) const {
    if (length < sizeof(long)) {
        LOG_ERROR("read memory length need > size of long");
        return false;
    }

    unsigned long n = 0;
    unsigned long piece = length % sizeof(long);

    if (piece) {
        long r = ptrace(PTRACE_PEEKTEXT, mPid, (unsigned char *)address + length - sizeof(long), nullptr);
        *(long *)((unsigned char *)buffer + length - sizeof(long)) = r;

        length -= piece;
    }

    while (n < length) {
        long r = ptrace(PTRACE_PEEKTEXT, mPid, (unsigned char *)address + n, nullptr);
        *(long *)((unsigned char *)buffer + n) = r;

        n += sizeof(long);
    }

    return true;
}

bool CPTInject::writeMemory(void *address, void *buffer, unsigned long length) const {
    if (length < sizeof(long)) {
        LOG_ERROR("write memory length need > size of long");
        return false;
    }

    unsigned long n = 0;
    unsigned long piece = length % sizeof(long);

    if (piece) {
        if (ptrace(PTRACE_POKETEXT, mPid, (unsigned char*)address + length - sizeof(long), *(long *)((unsigned char *)buffer + length - sizeof(long))) < 0) {
            LOG_ERROR("write memory failed");
            return false;
        }

        length -= piece;
    }

    while (n < length) {
        if (ptrace(PTRACE_POKETEXT, mPid, (unsigned char*)address + n, *(long *)((unsigned char *)buffer + n)) < 0) {
            LOG_ERROR("write memory failed");
            return false;
        }

        n += sizeof(long);
    }

    return true;
}

bool CPTInject::cancelSyscall() const {
#ifdef __arm__
    if (ptrace(PTRACE_SET_SYSCALL, mPid, nullptr, (void *)-1) < 0) {
        LOG_ERROR("cancel syscall failed");
        return false;
    }

#elif __aarch64__
    long sysNR = -1;

    iovec iov = {};

    iov.iov_base = &sysNR;
    iov.iov_len = sizeof(long);

    if (ptrace(PTRACE_SETREGSET, mPid, (void *)NT_ARM_SYSTEM_CALL, &iov) < 0) {
        LOG_ERROR("cancel syscall failed");
        return false;
    }

#else
    if (ptrace(PTRACE_POKEUSER, mPid, offsetof(CRegister, REG_SYSCALL), (void *)-1) < 0) {
        LOG_ERROR("cancel syscall failed");
        return false;
    }
#endif

    return true;
}

bool CPTInject::searchExecZone(void **base) const {
    std::list<CProcessMap> processMaps;

    if (!CProcess::getProcessMaps(mPid, processMaps)) {
        LOG_ERROR("get process maps failed");
        return false;
    }

    auto it = std::find_if(
            processMaps.begin(),
            processMaps.end(),
            [](const auto& m) {
                return m.flags == "r-xp" || m.flags == "rwxp";
            });

    if (it == processMaps.end())
        return false;

    *base = (void *)(*it).start;

    return true;
}

bool CPTInject::init() {
    std::string path = CPath::join("/proc", std::to_string(mPid), "task");

    for (const auto& i: CFileWalker(path)) {
        int thread = 0;

        if (!CStringHelper::toNumber(i.filename, thread)) {
            LOG_ERROR("parse thread id failed: %s", i.filename.c_str());
            return false;
        }

        mThreads.emplace_back(thread);
    }

    return true;
}
