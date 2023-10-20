#include "ptrace/executor.h"
#include "shellcode/alloc.h"
#include "shellcode/free.h"
#include "shellcode/loader.h"
#include "shellcode/loader/payload.h"
#include <zero/log.h>
#include <zero/cmdline.h>
#include <zero/os/procfs.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE       0x1000
#endif

constexpr auto ALLOC_SIZE = 0x21000;

int main(int argc, char *argv[]) {
    INIT_CONSOLE_LOG(zero::INFO_LEVEL);

    zero::Cmdline cmdline;

    cmdline.add<int>("pid", "process id");

    cmdline.addOptional("daemon", 'd', "daemon mode");
    cmdline.addOptional("deaf", '\0', "signal won't be delivered immediately");
    cmdline.addOptional<std::vector<std::string>>("environs", 'e', "environment variables");

    cmdline.footer("inject argv");
    cmdline.parse(argc, argv);

    int pid = cmdline.get<int>("pid");

    bool daemon = cmdline.exist("daemon");
    bool deaf = cmdline.exist("deaf");

    auto arguments = cmdline.rest();
    auto environs = cmdline.getOptional<std::vector<std::string>>("environs");

    if (arguments.empty()) {
        LOG_ERROR("inject empty argv");
        return -1;
    }

    LOG_INFO("exec %s", zero::strings::join(arguments, " ").c_str());

    auto process = zero::os::procfs::openProcess(pid);

    if (!process) {
        LOG_ERROR("open process %d failed[%s]", pid, process.error().message().c_str());
        return -1;
    }

    auto tasks = process->tasks();

    if (!tasks) {
        LOG_ERROR("get process tasks failed[%s]", tasks.error().message().c_str());
        return -1;
    }

    std::list<std::unique_ptr<Executor>> executors;

    std::transform(
            tasks->begin(),
            tasks->end(),
            std::back_inserter(executors),
            [=](const auto &tid) {
                return std::make_unique<Executor>(tid, deaf);
            }
    );

    if (!std::all_of(executors.begin(), executors.end(), [](const auto &executor) { return executor->attach(); })) {
        LOG_ERROR("attach threads failed");
        return -1;
    }

    std::string commandline = zero::strings::join(arguments, PAYLOAD_DELIMITER);

    if (commandline.length() >= sizeof(loader_payload_t::argv)) {
        LOG_ERROR("length of command line exceeds limit");
        return -1;
    }

    loader_payload_t payload = {daemon};

    memcpy(payload.argv, commandline.c_str(), commandline.length());

    if (environs) {
        std::string env = zero::strings::join(*environs, PAYLOAD_DELIMITER);

        if (env.length() >= sizeof(loader_payload_t::env)) {
            LOG_ERROR("length of environment variables exceeds limit");
            return -1;
        }

        memcpy(payload.env, env.c_str(), env.length());
    }

    LOG_INFO("execute alloc shellcode");

    std::unique_ptr<Executor> &executor = executors.front();
    std::optional<unsigned long> result = executor->call(alloc_sc, alloc_sc_len, 0, 0, 0);

    if (!result || !*result) {
        LOG_ERROR("execute alloc shellcode failed");
        return -1;
    }

    LOG_INFO("memory allocated: %p", result);

    std::optional<regs_t> regs = executor->getRegisters();
    std::optional<fp_regs_t> fp_regs = executor->getFPRegisters();

    if (!regs || !fp_regs) {
        LOG_ERROR("get executor context failed");
        return -1;
    }

    payload.context = {
            *regs,
            *fp_regs
    };

    if (!executor->writeMemory(*result, &payload, sizeof(payload))) {
        LOG_ERROR("write loader payload failed");
        return -1;
    }

    uintptr_t base = (*result + sizeof(payload) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    uintptr_t stack = *result + ALLOC_SIZE;

    LOG_INFO("execute loader shellcode");

    std::optional<int> status = executor->run(loader_sc, loader_sc_len, base, stack, *result);

    if (!status) {
        LOG_ERROR("execute loader shellcode failed");
        return -1;
    }

    LOG_INFO("execute free shellcode");

    if (!executor->call(free_sc, free_sc_len, 0, 0, *result)) {
        LOG_ERROR("execute free shellcode failed");
        return -1;
    }

    return *status;
}
