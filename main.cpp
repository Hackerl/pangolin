#include "inject/pt_inject.h"
#include "share/sh_args.h"
#include <spread/spread.h>
#include <shrink/shrink.h>
#include <loader/loader.h>
#include <common/cmdline.h>
#include <common/log.h>
#include <unistd.h>

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

    if (!base.empty())
        CStringHelper::toNumber(base, loaderArgs.base_address, 16);

    CShareArgs shareArgs(pid, command, env);

    if (!shareArgs.getLoaderArgs(loaderArgs))
        return -1;

    LOG_INFO("inject '%s' to process %d at 0x%lx", loaderArgs.arg, pid, loaderArgs.base_address);

    CPTInject ptInject(pid);

    if (!ptInject.attach())
        return -1;

    void *result = nullptr;

    if (!ptInject.callCode("libspread.so", nullptr, (void *)0x10000, &result)) {
        return -1;
    }

    LOG_INFO("malloc memory: 0x%lx", (unsigned long)result);

    ptInject.writeMemory(result, &loaderArgs, sizeof(loaderArgs));

    auto injectBase = (unsigned long)result + PAGE_SIZE - (unsigned long)result % PAGE_SIZE;

    if (!ptInject.runCode("libloader.so", (void *)injectBase, result)) {
        return -1;
    }

    LOG_INFO("free memory: 0x%lx", (unsigned long)result);

    if (!ptInject.callCode("libshrink.so", nullptr, result, nullptr)) {
        return -1;
    }

    ptInject.detach();

    return 0;
}
