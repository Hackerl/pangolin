#include "pt_inject.h"
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <elf.h>
#include <sys/reg.h>
#include <memory>
#include <sys/wait.h>
#include <syscall.h>
#include <common/log.h>
#include <dlfcn.h>
#include <common/utils/path.h>

CPTInject::CPTInject(int pid) {
    mPid = pid;
    mAttached = false;
}

CPTInject::~CPTInject() {
    if (mAttached)
        detach();
}

bool CPTInject::attach() {
    if (ptrace(PTRACE_ATTACH, mPid, nullptr, nullptr) < 0) {
        LOG_ERROR("attach process failed");
        return false;
    }

    int s = 0;

    if (waitpid(mPid, &s, WUNTRACED) != mPid) {
        LOG_ERROR("wait pid failed");
        return false;
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

    if (ptrace(PTRACE_DETACH, mPid, nullptr, nullptr) < 0) {
        LOG_ERROR("detach process failed");
        return false;
    }

    LOG_INFO("detach process success");

    mAttached = false;
    return true;
}

bool CPTInject::runCode(const char *shellcode, void *base, void *arg) const {
    void *begin = nullptr;
    void *entry = nullptr;
    void *end = nullptr;

    if (!loadShellcode(shellcode, &begin, &entry, &end))
        return false;

    unsigned long offset = (unsigned long)entry - (unsigned long)begin;
    unsigned long length = (unsigned long)end - (unsigned long)begin;

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

    if (!writeMemory(memoryBase, begin, length))
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

bool CPTInject::callCode(const char *shellcode, void *base, void *arg, void **result) const {
    void *begin = nullptr;
    void *entry = nullptr;
    void *end = nullptr;

    if (!loadShellcode(shellcode, &begin, &entry, &end))
        return false;

    unsigned long offset = (unsigned long)entry - (unsigned long)begin;
    unsigned long length = (unsigned long)end - (unsigned long)begin;

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

    if (!writeMemory(memoryBase, begin, length))
        return false;

    user_regs_struct modifyRegs = mRegister;

    modifyRegs.rdi = (unsigned long long)arg;
    modifyRegs.rip = (unsigned long long)memoryBase + 2 + offset;

    if (!setRegister(modifyRegs))
        return false;

    if (ptrace(PTRACE_CONT, mPid, nullptr, nullptr) < 0) {
        LOG_ERROR("trace continue failed");
        return false;
    }

    int s = 0;

    if (waitpid(mPid, &s, 0) < 0 || WIFEXITED(s)) {
        LOG_ERROR("wait pid failed");
        return false;
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

bool CPTInject::loadShellcode(const char *name, void **begin, void **entry, void **end) {
    LOG_INFO("load shellcode %s", name);

    std::string path = CPath::join(CPath::getAPPDir(), name);

    void* DLHandle = dlopen(path.c_str(), RTLD_LAZY);

    if (!DLHandle)
        return false;

    *begin = dlsym(DLHandle, "shellcode_begin");
    *entry = dlsym(DLHandle, "shellcode_start");
    *end = dlsym(DLHandle, "shellcode_end");

    if (!*begin || !*entry || !*end) {
        LOG_ERROR("load shellcode failed");

        dlclose(DLHandle);
        return false;
    }

    return true;
}
