#include "ptrace/injector.h"
#include <common/cmdline.h>
#include <common/log.h>
#include <loader/payload.h>

constexpr auto ALLOC_SIZE = 0x21000;

int main(int argc, char ** argv) {
    cmdline::parser parse;

    parse.add("daemon", '\0', "daemon mode");
    parse.add<int>("pid", 'p', "process id", true, 0);

    parse.add<std::string>("commandline", 'c', "commandline executed in process", true, "");
    parse.add<std::string>("env", 'e', "environment variable", false, "");

    parse.parse_check(argc, argv);

    INIT_CONSOLE_LOG(INFO);

    int pid = parse.get<int>("pid");

    std::string commandline = parse.get<std::string>("commandline");
    std::string env = parse.get<std::string>("env");

    LOG_INFO("inject '%s' to process %d", commandline.c_str(), pid);

    CInjector injector(pid);

    if (!injector.init()) {
        LOG_ERROR("injector init failed");
        return -1;
    }

    if (!injector.attach()) {
        LOG_ERROR("injector attach failed");
        return -1;
    }

    void *result = nullptr;

    if (!injector.call("alloc", nullptr, nullptr, nullptr, &result)) {
        LOG_ERROR("spread shellcode execute failed");
        return -1;
    }

    LOG_INFO("workspace: %p", result);

    std::list<std::string> arguments;
    std::list<std::string> environs;

    if (!CShellAPI::expansion(commandline, arguments) || !CShellAPI::expansion(env, environs)) {
        LOG_ERROR("commandline expansion failed");
        return -1;
    }

    std::string combinedArg = CStringHelper::join(arguments, PAYLOAD_DELIMITER);
    std::string combinedEnv = CStringHelper::join(environs, PAYLOAD_DELIMITER);

    if (combinedArg.size() >= sizeof(loader_payload_t::argv) || combinedEnv.size() >= sizeof(loader_payload_t::env)) {
        LOG_ERROR("payload size limit");
        return -1;
    }

    loader_payload_t payload = {};

    payload.daemon = parse.exist("daemon");

    memcpy(payload.argv, combinedArg.data(), combinedArg.size());
    memcpy(payload.env, combinedEnv.data(), combinedEnv.size());

    injector.writeMemory(result, &payload, sizeof(payload));

    int status = 0;

    unsigned long pageSize = sysconf(_SC_PAGESIZE);
    unsigned long base = ((unsigned long)result + sizeof(payload) + pageSize - 1) & ~(pageSize - 1);
    unsigned long stack = (unsigned long)result + ALLOC_SIZE;

    if (!injector.run("loader", (void *)base, (void *)stack, result, status)) {
        LOG_ERROR("loader shellcode execute failed");
        return -1;
    }

    LOG_INFO("free workspace");

    if (!injector.call("free", nullptr, nullptr, result, nullptr)) {
        LOG_ERROR("shrink shellcode execute failed");
        return -1;
    }

    injector.detach();

    return status;
}
