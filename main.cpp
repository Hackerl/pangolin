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

    parse.add<int>("pid", 'p', "pid", false, 0);

    parse.add<std::string>("file", 'f', "file", true, "");
    parse.add<std::string>("arg", 'a', "arg", false, "");
    parse.add<std::string>("env", 'e', "env", false, "");
    parse.add<std::string>("base", 'b', "base address", false, "");

    parse.parse_check(argc, argv);

    int pid = parse.get<int>("pid");

    std::string file = parse.get<std::string>("file");
    std::string arg = parse.get<std::string>("arg");
    std::string env = parse.get<std::string>("env");
    std::string base = parse.get<std::string>("base");

    CLoaderArgs loaderArgs = {};

    if (!base.empty())
        CStringHelper::toNumber(base, loaderArgs.base_address, 16);

    if (pid == 0) {
        LOG_INFO("self inject");

        CShareArgs shareArgs(getpid(), file, arg, env);

        if (!shareArgs.getLoaderArgs(loaderArgs))
            return -1;

        loader_self(&loaderArgs);

        return 0;
    }

    CShareArgs shareArgs(pid, file, arg, env);

    if (!shareArgs.getLoaderArgs(loaderArgs))
        return -1;

    LOG_INFO("inject %s to %d at 0x%lx", file.c_str(), pid, loaderArgs.base_address);

    CPTInject ptInject(pid);

    if (!ptInject.attach())
        return -1;

    void *result = nullptr;

    if (!ptInject.callCode((void*)spread_begin, (unsigned long)spread_end - (unsigned long)spread_begin,
                           (unsigned long)spread_start - (unsigned long)spread_begin,
                           nullptr, (void *)0x10000, &result)) {
        return -1;
    }

    LOG_INFO("malloc memory: 0x%lx", (unsigned long)result);

    ptInject.writeMemory(result, &loaderArgs, sizeof(loaderArgs));

    auto injectBase = (unsigned long)result + PAGE_SIZE - (unsigned long)result % PAGE_SIZE;
    auto injectBegin = (unsigned long)loader_begin;

    injectBegin -= injectBegin % PAGE_SIZE;

    if (!ptInject.runCode((void*)injectBegin, (unsigned long)loader_end() - injectBegin,
                          (unsigned long)loader_start - injectBegin,
                          (void *)injectBase, result)) {
        return -1;
    }

    LOG_INFO("free memory: 0x%lx", (unsigned long)result);

    if (!ptInject.callCode((void*)shrink_begin, (unsigned long)shrink_end - (unsigned long)shrink_begin,
                           (unsigned long)shrink_start - (unsigned long)shrink_begin,
                           nullptr, result, nullptr)) {
        return -1;
    }

    ptInject.detach();

    return 0;
}
