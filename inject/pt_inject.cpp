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

bool CPTInject::runCode(const char *filename, void *base, void *arg) const {
    CShellcode shellcode;

    if (!shellcode.open(filename) || !shellcode.load()) {
        LOG_ERROR("shellcode load failed");
        return false;
    }

    unsigned long begin = shellcode.getBegin();
    unsigned long entry = shellcode.getEntry();
    unsigned long end = shellcode.getEnd();

    unsigned long offset = entry - begin;
    unsigned long length = end - begin;

    void *memoryBase = base;
    std::unique_ptr<unsigned char> memoryBackup(new unsigned char[length + sizeof(long)]());

    if (!memoryBase && !searchExecZone(&memoryBase)) {
        LOG_ERROR("search execute zone failed");
        return false;
    }

    LOG_INFO("backup memory");

    if (!readMemory(memoryBase, memoryBackup.get(), length))
        return false;

    LOG_INFO("inject code at: 0x%lx entry: 0x%lx size: 0x%lx", (unsigned long)memoryBase, offset, length);

    if (!writeMemory(memoryBase, (void *)begin, length))
        return false;

    user_regs_struct modifyRegs = mRegister;

    modifyRegs.rdi = (unsigned long long)arg;
    modifyRegs.rip = (unsigned long long)memoryBase + 2 + offset;

    if (!setRegister(modifyRegs))
        return false;

    while (true) {
        if (ptrace(PTRACE_SYSCALL, mPid, nullptr, nullptr) < 0) {
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

        if (WSTOPSIG(s) == SIGSEGV){
            LOG_ERROR("segmentation fault: 0x%llx", currentRegs.rip);
            break;
        }

        if (currentRegs.orig_rax == -1) {
            LOG_INFO("break exit syscall");
            break;
        }

        if (currentRegs.orig_rax == SYS_exit || currentRegs.orig_rax == SYS_exit_group) {
            LOG_INFO("cancel exit syscall");
            cancelSyscall();
        }
    }

    LOG_INFO("restore memory");

    if (!writeMemory(memoryBase, memoryBackup.get(), length))
        return false;

    return true;
}

bool CPTInject::callCode(const char *filename, void *base, void *arg, void **result) const {
    CShellcode shellcode;

    if (!shellcode.open(filename) || !shellcode.load()) {
        LOG_ERROR("shellcode load failed");
        return false;
    }

    unsigned long begin = shellcode.getBegin();
    unsigned long entry = shellcode.getEntry();
    unsigned long end = shellcode.getEnd();

    unsigned long offset = entry - begin;
    unsigned long length = end - begin;

    void *memoryBase = base;
    std::unique_ptr<unsigned char> memoryBackup(new unsigned char[length + sizeof(long)]());

    if (!memoryBase && !searchExecZone(&memoryBase)) {
        LOG_ERROR("search execute zone failed");
        return false;
    }

    LOG_INFO("backup memory");

    if (!readMemory(memoryBase, memoryBackup.get(), length))
        return false;

    LOG_INFO("inject code at: 0x%lx entry: 0x%lx size: 0x%lx", (unsigned long)memoryBase, offset, length);

    if (!writeMemory(memoryBase, (void *)begin, length))
        return false;

    user_regs_struct modifyRegs = mRegister;

    modifyRegs.rdi = (unsigned long long)arg;
    modifyRegs.rip = (unsigned long long)memoryBase + 2 + offset;

    if (!setRegister(modifyRegs))
        return false;

    int s = 0;

    while (true) {
        if (ptrace(PTRACE_CONT, mPid, nullptr, nullptr) < 0) {
            LOG_ERROR("trace continue failed");
            return false;
        }

        if (waitpid(mPid, &s, 0) < 0 || WIFEXITED(s)) {
            LOG_ERROR("wait pid failed");
            return false;
        }

        if (WSTOPSIG(s) == SIGTRAP || WSTOPSIG(s) == SIGSEGV)
            break;
    }

    LOG_INFO("restore memory");

    if (!writeMemory(memoryBase, memoryBackup.get(), length))
        return false;

    user_regs_struct currentRegs = {};

    if (!getRegister(currentRegs))
        return false;

    if (WSTOPSIG(s) == SIGSEGV) {
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

    bool found = false;

    for (const auto& m: processMaps) {
        if (m.flags == "r-xp" || m.flags == "rwxp") {
            found = true;
            *base = (void *)m.start;
            break;
        }
    }

    return found;
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
