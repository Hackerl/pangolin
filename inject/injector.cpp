#include "injector.h"
#include <zero/log.h>
#include <zero/proc/process.h>
#include <shellcode/alloc.h>
#include <shellcode/free.h>
#include <shellcode/loader.h>
#include <shellcode/loader/payload.h>
#include <unistd.h>

constexpr auto ALLOC_SIZE = 0x21000;

CInjector::~CInjector() {
    for (const auto &executor : mExecutors) {
        executor->detach();
        delete executor;
    }
}

bool CInjector::open(pid_t pid) {
    std::list<pid_t> threads;

    if (!zero::proc::getThreads(pid, threads)) {
        LOG_ERROR("get process %d threads failed", pid);
        return false;
    }

    for (const auto &tid : threads) {
        std::unique_ptr<CExecutor> executor(new CExecutor(tid));

        if (!executor->attach())
            return false;

        mExecutors.push_back(executor.release());
    }

    LOG_INFO("attach process %d success", pid);

    return true;
}

int CInjector::inject(const std::vector<std::string>& arguments, const std::vector<std::string>& environs, bool daemon) {
    std::string combinedArg = zero::strings::join(arguments, PAYLOAD_DELIMITER);
    std::string combinedEnv = zero::strings::join(environs, PAYLOAD_DELIMITER);

    if (combinedArg.size() >= sizeof(loader_payload_t::argv) || combinedEnv.size() >= sizeof(loader_payload_t::env)) {
        LOG_ERROR("payload size limit");
        return -1;
    }

    loader_payload_t payload = {daemon};

    memcpy(payload.argv, combinedArg.data(), combinedArg.size());
    memcpy(payload.env, combinedEnv.data(), combinedEnv.size());

    void *result = nullptr;
    CExecutor *executor = mExecutors.front();

    LOG_INFO("execute alloc shellcode");

    if (!executor->call(alloc_sc, alloc_sc_len, nullptr, nullptr, nullptr, &result)) {
        LOG_ERROR("execute alloc shellcode failed");
        return -1;
    }

    if (!result) {
        LOG_INFO("allocate memory failed");
        return -1;
    }

    LOG_INFO("memory allocated: %p", result);

    if (!executor->getRegisters(payload.regs)) {
        LOG_ERROR("get registers failed");
        return -1;
    }

    if (!executor->writeMemory(result, &payload, sizeof(payload))) {
        LOG_ERROR("write loader payload failed");
        return -1;
    }

    int status = 0;

    unsigned long pageSize = sysconf(_SC_PAGESIZE);
    unsigned long base = ((unsigned long)result + sizeof(payload) + pageSize - 1) & ~(pageSize - 1);
    unsigned long stack = (unsigned long)result + ALLOC_SIZE;

    LOG_INFO("execute loader shellcode");

    if (!executor->run(loader_sc, loader_sc_len, (void *)base, (void *)stack, result, status)) {
        LOG_ERROR("execute loader shellcode failed");
        return -1;
    }

    LOG_INFO("execute free shellcode");

    if (!executor->call(free_sc, free_sc_len, nullptr, nullptr, result, nullptr)) {
        LOG_ERROR("execute free shellcode failed");
        return -1;
    }

    return status;
}
