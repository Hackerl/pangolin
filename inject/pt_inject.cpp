#include "pt_inject.h"
#include "shellcode.h"
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <elf.h>
#include <sys/reg.h>
#include <memory>
#include <sys/wait.h>
#include <syscall.h>
#include <common/log.h>
#include <common/utils/process.h>
#include <common/utils/file_walk.h>

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
            LOG_ERROR("attach recv signal: %s", strsignal(WSTOPSIG(s)));
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

bool CPTInject::runCode(const char *name, void *base, void *arg, int &status) const {
    CShellcode shellcode;

    if (!shellcode.load(name)) {
        LOG_ERROR("shellcode load failed");
        return false;
    }

    unsigned long offset = shellcode.mEntry - shellcode.mBegin;
    unsigned long length = shellcode.mEnd - shellcode.mBegin;

    void *memoryBase = base;
    std::unique_ptr<unsigned char> memoryBackup(new unsigned char[length + sizeof(long)]());

    if (!memoryBase && !searchExecZone(&memoryBase)) {
        LOG_ERROR("search execute zone failed");
        return false;
    }

    LOG_INFO("backup memory");

    if (!readMemory(memoryBase, memoryBackup.get(), length))
        return false;

    LOG_INFO("inject code at: %p entry: 0x%lx size: 0x%lx", memoryBase, offset, length);

    if (!writeMemory(memoryBase, (void *)shellcode.mBegin, length))
        return false;

    user_regs_struct modifyRegs = mRegister;

    modifyRegs.rdi = (unsigned long long)arg;
    modifyRegs.rip = (unsigned long long)memoryBase + 2 + offset;

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

        user_regs_struct currentRegs = {};

        if (!getRegister(currentRegs))
            return false;

        sig = WSTOPSIG(s);

        if (sig == SIGSEGV) {
            LOG_ERROR("segmentation fault: 0x%llx", currentRegs.rip);
            break;
        }

        if (sig != SIGTRAP) {
            LOG_INFO("recv signal: %s", strsignal(sig));
            continue;
        }

        sig = 0;

        if (currentRegs.orig_rax == -1) {
            LOG_INFO("exit status: %d", status);
            break;
        }

        if (currentRegs.orig_rax == SYS_exit || currentRegs.orig_rax == SYS_exit_group) {
            status = (int)currentRegs.rdi;
            cancelSyscall();
        }
    }

    LOG_INFO("restore memory");

    if (!writeMemory(memoryBase, memoryBackup.get(), length))
        return false;

    return sig != SIGSEGV;
}

bool CPTInject::callCode(const char *name, void *base, void *arg, void **result) const {
    CShellcode shellcode;

    if (!shellcode.load(name)) {
        LOG_ERROR("shellcode load failed");
        return false;
    }

    unsigned long offset = shellcode.mEntry - shellcode.mBegin;
    unsigned long length = shellcode.mEnd - shellcode.mBegin;

    void *memoryBase = base;
    std::unique_ptr<unsigned char> memoryBackup(new unsigned char[length + sizeof(long)]());

    if (!memoryBase && !searchExecZone(&memoryBase)) {
        LOG_ERROR("search execute zone failed");
        return false;
    }

    LOG_INFO("backup memory");

    if (!readMemory(memoryBase, memoryBackup.get(), length))
        return false;

    LOG_INFO("inject code at: %p entry: 0x%lx size: 0x%lx", memoryBase, offset, length);

    if (!writeMemory(memoryBase, (void *)shellcode.mBegin, length))
        return false;

    user_regs_struct modifyRegs = mRegister;

    modifyRegs.rdi = (unsigned long long)arg;
    modifyRegs.rip = (unsigned long long)memoryBase + 2 + offset;

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

        LOG_INFO("recv signal: %s", strsignal(sig));
    }

    LOG_INFO("restore memory");

    if (!writeMemory(memoryBase, memoryBackup.get(), length))
        return false;

    user_regs_struct currentRegs = {};

    if (!getRegister(currentRegs))
        return false;

    if (sig == SIGSEGV) {
        LOG_ERROR("segmentation fault: 0x%llx", currentRegs.rip);
        return false;
    }

    if (result)
        *result = (void *)currentRegs.rax;

    return true;
}

bool CPTInject::getRegister(user_regs_struct &regs) const {
    iovec io = {};

    io.iov_base = &regs;
    io.iov_len = sizeof(user_regs_struct);

    if (ptrace(PTRACE_GETREGSET, mPid, (void*)NT_PRSTATUS, (void*)&io) < 0) {
        LOG_ERROR("get register failed: %s", strerror(errno));
        return false;
    }

    return true;
}

bool CPTInject::setRegister(user_regs_struct regs) const {
    iovec io = {};

    io.iov_base = &regs;
    io.iov_len = sizeof(user_regs_struct);

    if (ptrace(PTRACE_SETREGSET, mPid, (void*)NT_PRSTATUS, (void*)&io) < 0) {
        LOG_ERROR("set register failed");
        return false;
    }

    return true;
}

bool CPTInject::readMemory(void *address, void *buffer, unsigned long length) const {
    if (length < sizeof(long)) {
        LOG_ERROR("read memory length need > 8");
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
        LOG_ERROR("write memory length need > 8");
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
    if (ptrace(PTRACE_POKEUSER, mPid, (sizeof(unsigned long) * ORIG_RAX), (void *)-1) < 0) {
        LOG_ERROR("cancel syscall failed");
        return false;
    }

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

    for (const auto& i: CFileWalk(path.c_str())) {
        int thread = 0;

        if (!CStringHelper::toNumber(i.filename, thread)) {
            LOG_ERROR("parse thread id failed: %s", i.filename.c_str());
            return false;
        }

        mThreads.emplace_back(thread);
    }

    return true;
}
