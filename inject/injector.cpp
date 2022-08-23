#include "injector.h"
#include <zero/log.h>
#include <zero/proc/process.h>
#include <shellcode/alloc.h>
#include <shellcode/free.h>
#include <shellcode/loader.h>
#include <shellcode/loader/payload.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE       0x1000
#endif

constexpr auto ALLOC_SIZE = 0x21000;

Injector::~Injector() {
    for (const auto &executor : mExecutors) {
        std::ignore = executor->detach();
        delete executor;
    }
}

bool Injector::open(pid_t pid, bool deaf) {
    std::optional<std::list<pid_t>> threads = zero::proc::getThreads(pid);

    if (!threads) {
        LOG_ERROR("get process %d threads failed", pid);
        return false;
    }

    for (const auto &tid : *threads) {
        std::unique_ptr<Executor> executor(new Executor(tid, deaf));

        if (!executor->attach())
            return false;

        mExecutors.push_back(executor.release());
    }

    LOG_INFO("attach process %d success", pid);

    return true;
}

int Injector::inject(const std::vector<std::string>& arguments, const std::vector<std::string>& environs, bool daemon) {
    std::string combinedArg = zero::strings::join(arguments, PAYLOAD_DELIMITER);
    std::string combinedEnv = zero::strings::join(environs, PAYLOAD_DELIMITER);

    if (combinedArg.size() >= sizeof(loader_payload_t::argv) || combinedEnv.size() >= sizeof(loader_payload_t::env)) {
        LOG_ERROR("payload size limit");
        return -1;
    }

    loader_payload_t payload = {daemon};

    memcpy(payload.argv, combinedArg.data(), combinedArg.size());
    memcpy(payload.env, combinedEnv.data(), combinedEnv.size());

    LOG_INFO("execute alloc shellcode");

    Executor *executor = mExecutors.front();
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
