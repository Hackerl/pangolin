#include "executor.h"
#include <zero/log.h>
#include <zero/proc/process.h>
#include <algorithm>
#include <sys/wait.h>
#include <syscall.h>

#ifdef __i386__

#define REG_PC              eip
#define REG_RET             eax
#define REG_STACK           esp
#define PC_OFFSET           2
#define REG_SYSCALL         orig_eax
#define REG_SYSCALL_ARG     ebx
#define REG_SYSCALL_ARG1    ecx
#define REG_SYSCALL_ARG2    edx

#elif __x86_64__

#define REG_PC              rip
#define REG_ARG             rdi
#define REG_RET             rax
#define REG_STACK           rsp
#define PC_OFFSET           2
#define REG_SYSCALL         orig_rax
#define REG_SYSCALL_ARG     rdi
#define REG_SYSCALL_ARG1    rsi
#define REG_SYSCALL_ARG2    rdx

#elif __arm__

#define REG_PC              uregs[15]
#define REG_ARG             uregs[0]
#define REG_RET             uregs[0]
#define REG_STACK           uregs[13]
#define PC_OFFSET           4
#define REG_SYSCALL         uregs[7]
#define REG_SYSCALL_ARG     uregs[0]
#define REG_SYSCALL_ARG1    uregs[1]
#define REG_SYSCALL_ARG2    uregs[2]

#elif __aarch64__

#define REG_PC              pc
#define REG_ARG             regs[0]
#define REG_RET             regs[0]
#define REG_STACK           sp
#define PC_OFFSET           4
#define REG_SYSCALL         regs[8]
#define REG_SYSCALL_ARG     regs[0]
#define REG_SYSCALL_ARG1    regs[1]
#define REG_SYSCALL_ARG2    regs[2]

#else
#error "unknown arch"
#endif

constexpr auto PRIVATE_EXIT_MAGIC = 0x6861636b;

constexpr auto PRIVATE_EXIT_SYSCALL = -1;
constexpr auto PRIVATE_CANCEL_SYSCALL = -2;

CExecutor::CExecutor(pid_t pid) : CTracee(pid) {

}

bool CExecutor::run(const unsigned char *shellcode, unsigned int length, void *base, void *stack, void *argument, int &status) {
    std::unique_ptr<unsigned char> buffer(new unsigned char[length]());

    if (!base && !getExecBase(&base)) {
        LOG_ERROR("get executable memory base failed");
        return false;
    }

    LOG_INFO("write shellcode: %p[0x%lx]", base, length);

    if (!readMemory(base, buffer.get(), length))
        return false;

    if (!writeMemory(base, (void *)shellcode, length))
        return false;

    regs_t regs = {};

    if (!getRegisters(regs))
        return false;

    LOG_INFO("entry: %p stack: %p argument: %p", base, stack, argument);

    regs_t modify = regs;

    modify.REG_PC = (unsigned long)base + PC_OFFSET;
    modify.REG_STACK = stack ? (unsigned long)stack : modify.REG_STACK;

#ifdef __i386__
    if (!writeMemory((char *)modify.REG_STACK - sizeof(arg), &arg, sizeof(arg)))
        return false;

    modify.REG_STACK -= sizeof(arg);
#else
    modify.REG_ARG = (unsigned long)argument;
#endif

    if (!setRegisters(modify))
        return false;

    int sig = 0;

    while (true) {
        if (!catchSyscall(sig))
            return false;

        int s = 0;

        if (waitpid(mPID, &s, 0) < 0) {
            LOG_ERROR("wait pid failed: %s", strerror(errno));
            return false;
        }

        if (WIFSIGNALED(s)) {
            LOG_WARNING("process terminated: %s", strsignal(WTERMSIG(s)));
            return false;
        }

        regs_t current = {};

        if (!getRegisters(current))
            return false;

        sig = WSTOPSIG(s);

        if (sig == SIGSEGV) {
            LOG_ERROR("segmentation fault: 0x%lx", current.REG_PC);
            break;
        }

        if (sig != SIGTRAP) {
            LOG_INFO("receive signal: %s", strsignal(sig));
            continue;
        }

        sig = 0;

#if __i386__ || __x86_64__
        if (current.REG_SYSCALL == PRIVATE_CANCEL_SYSCALL) {
            LOG_INFO("catch exit syscall: %d", status);
            break;
        }
#endif

        if ((int)current.REG_SYSCALL == PRIVATE_EXIT_SYSCALL && current.REG_SYSCALL_ARG1 == PRIVATE_EXIT_MAGIC) {
            status = (int)current.REG_SYSCALL_ARG2;

#if __i386__ || __x86_64__
            setSyscall(PRIVATE_CANCEL_SYSCALL);
#elif __arm__ || __aarch64__
            LOG_INFO("catch exit syscall: %d", status);
            break;
#endif
        }

        if (current.REG_SYSCALL == SYS_exit || current.REG_SYSCALL == SYS_exit_group) {
            status = (int)current.REG_SYSCALL_ARG;
            setSyscall(PRIVATE_CANCEL_SYSCALL);

#if __arm__ || __aarch64__
            LOG_INFO("catch exit syscall: %d", status);
            break;
#endif
        }
    }

    if (!writeMemory(base, buffer.get(), length))
        return false;

    if (!setRegisters(regs))
        return false;

    return sig != SIGSEGV;
}

bool CExecutor::call(const unsigned char *shellcode, unsigned int length, void *base, void *stack, void *argument, void **result) {
    std::unique_ptr<unsigned char> buffer(new unsigned char[length]());

    if (!base && !getExecBase(&base)) {
        LOG_ERROR("get executable memory base failed");
        return false;
    }

    LOG_INFO("write shellcode: %p[0x%lx]", base, length);

    if (!readMemory(base, buffer.get(), length))
        return false;

    if (!writeMemory(base, (void *)shellcode, length))
        return false;

    regs_t regs = {};

    if (!getRegisters(regs))
        return false;

    LOG_INFO("entry: %p stack: %p argument: %p", base, stack, argument);

    regs_t modify = regs;

    modify.REG_PC = (unsigned long)base + PC_OFFSET;
    modify.REG_STACK = stack ? (unsigned long)stack : modify.REG_STACK;

#ifdef __i386__
    if (!writeMemory((char *)modify.REG_STACK - sizeof(arg), &arg, sizeof(arg)))
        return false;

    modify.REG_STACK -= sizeof(arg);
#else
    modify.REG_ARG = (unsigned long)argument;
#endif

    if (!setRegisters(modify))
        return false;

    int sig = 0;

    while (true) {
        if (!resume(sig))
            return false;

        int s = 0;

        if (waitpid(mPID, &s, 0) < 0) {
            LOG_ERROR("wait pid failed: %s", strerror(errno));
            return false;
        }

        if (WIFSIGNALED(s)) {
            LOG_WARNING("process terminated: %s", strsignal(WTERMSIG(s)));
            return false;
        }

        regs_t current = {};

        if (!getRegisters(current))
            return false;

        sig = WSTOPSIG(s);

        if (sig == SIGSEGV) {
            LOG_ERROR("segmentation fault: 0x%lx", current.REG_PC);
            break;
        }

        if (sig == SIGTRAP) {
            if (result)
                *result = (void *)current.REG_RET;

            break;
        }

        LOG_INFO("receive signal: %s", strsignal(sig));
    }

    if (!writeMemory(base, buffer.get(), length))
        return false;

    if (!setRegisters(regs))
        return false;

    return sig != SIGSEGV;
}

bool CExecutor::getExecBase(void **base) const {
    std::list<zero::proc::CProcessMapping> processMappings;

    if (!zero::proc::getProcessMappings(mPID, processMappings)) {
        LOG_ERROR("get process %d memory mappings failed", mPID);
        return false;
    }

    auto it = std::find_if(
            processMappings.begin(),
            processMappings.end(),
            [](const auto &m) {
                return (m.permissions & zero::proc::READ_PERMISSION) &&
                       (m.permissions & zero::proc::EXECUTE_PERMISSION) &&
                       (m.permissions & zero::proc::PRIVATE_PERMISSION);
            });

    if (it == processMappings.end())
        return false;

    *base = (void *)(*it).start;

    return true;
}
