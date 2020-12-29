#include "inject/pt_inject.h"
#include "share/sh_args.h"
#include <common/cmdline.h>
#include <common/log.h>
#include <common/utils/string_helper.h>

constexpr auto PANGOLIN_WORKSPACE_SIZE = 0x10000;

constexpr auto SPREAD_SHELLCODE = "libspread.so";
constexpr auto LOADER_SHELLCODE = "libloader.so";
constexpr auto SHRINK_SHELLCODE = "libshrink.so";

int main(int argc, char ** argv) {
    cmdline::parser parse;

    parse.add<int>("pid", 'p', "pid", true, 0);

    parse.add<std::string>("command", 'c', "command line", true, "");
    parse.add<std::string>("env", 'e', "env", false, "");
    parse.add<std::string>("base", 'b', "base address", false, "");

    parse.parse_check(argc, argv);

    int pid = parse.get<int>("pid");

    std::string command = parse.get<std::string>("command");
    std::string env = parse.get<std::string>("env");
    std::string base = parse.get<std::string>("base");

    CLoaderArgs loaderArgs = {};

    if (!base.empty()) {
        LOG_INFO("custom base address: %s", base.c_str());
        CStringHelper::toNumber(base, loaderArgs.base_address, 16);
    }

    CShareArgs shareArgs(pid, command, env);

    if (!shareArgs.getLoaderArgs(loaderArgs)) {
        LOG_ERROR("get loader arguments failed");
        return -1;
    }

    LOG_INFO("inject '%s' to process %d at 0x%lx", loaderArgs.arg, pid, loaderArgs.base_address);

    CPTInject ptInject(pid);

    if (!ptInject.init()) {
        LOG_ERROR("ptrace injector init failed");
        return -1;
    }

    if (!ptInject.attach()) {
        LOG_ERROR("ptrace injector attach failed");
        return -1;
    }

    void *result = nullptr;

    if (!ptInject.callCode(SPREAD_SHELLCODE, nullptr, (void *)PANGOLIN_WORKSPACE_SIZE, &result)) {
        LOG_ERROR("call spread shellcode failed");
        return -1;
    }

    LOG_INFO("workspace: %p", result);

    ptInject.writeMemory(result, &loaderArgs, sizeof(loaderArgs));

    int status = 0;
    unsigned long injectBase = ((unsigned long)result + PAGE_SIZE) & ~(PAGE_SIZE - 1);

    if (!ptInject.runCode(LOADER_SHELLCODE, (void *)injectBase, result, status)) {
        LOG_ERROR("run loader shellcode failed");
        return -1;
    }

    LOG_INFO("free workspace: %p", result);

    if (!ptInject.callCode(SHRINK_SHELLCODE, nullptr, result, nullptr)) {
        LOG_ERROR("call shrink shellcode failed");
        return -1;
    }

    ptInject.detach();

    return status;
}
