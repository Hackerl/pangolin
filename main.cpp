#include "inject/pt_inject.h"
#include <spread/spread.h>
#include <shrink/shrink.h>
#include <loader/loader.h>
#include <loader/args.h>
#include <common/cmdline.h>
#include <common/log.h>
#include <memory>
#include <unistd.h>

int main(int argc, char ** argv) {
    cmdline::parser parse;

    parse.add<int>("pid", 'p', "pid", false, 0);
    parse.add<std::string>("file", 'f', "inject file", true, "");

    parse.parse_check(argc, argv);

    int pid = parse.get<int>("pid");
    std::string injectFile = parse.get<std::string>("file");

    LOG_INFO("inject %s to %d", injectFile.c_str(), pid);

    std::list<CProcessMap> processMaps;

    if (!CProcess::getProcessMaps(pid ? pid : getpid(), processMaps)) {
        LOG_ERROR("get process maps failed");
        return -1;
    }

    unsigned long baseAddress = 0;

    for (const auto& m: processMaps) {
        if (m.start > 0x7f0000000000)
            break;

        baseAddress = m.end + 0x01000000 - (m.end % 0x01000000);
    }

    unsigned long argSize = sizeof(CLoaderArgs) + injectFile.size() + 1;
    std::unique_ptr<CLoaderArgs> loaderArgs((CLoaderArgs*)new char[argSize]());

    loaderArgs->size = argSize;
    loaderArgs->arg_count = 1;
    loaderArgs->base_address = baseAddress;

    strcpy(loaderArgs->data, injectFile.data());

    if (pid == 0) {
        LOG_INFO("self inject");
        loader_self((void *)loaderArgs.get());
        return 0;
    }

    CPTInject ptInject(pid);

    if (!ptInject.attach())
        return -1;

    void *result = nullptr;

    if (!ptInject.callCode((void*)spread_begin, (unsigned long)spread_end - (unsigned long)spread_begin,
                           (unsigned long)spread_start - (unsigned long)spread_begin,
                           nullptr, (void *)0x10000, &result)) {
        return -1;
    }

    LOG_INFO("malloc memory: %lx", (unsigned long)result);

    ptInject.writeMemory(result, loaderArgs.get(), loaderArgs->size);

    auto base = (unsigned long)result + PAGE_SIZE - (unsigned long)result % PAGE_SIZE;

    if (!ptInject.runCode((void*)loader_begin(), (unsigned long)loader_end() - (unsigned long)loader_begin(),
                           (unsigned long)loader_start - (unsigned long)loader_begin(),
                           (void *)base, result)) {
        return -1;
    }

    LOG_INFO("free memory: %lx", (unsigned long)result);

    if (!ptInject.callCode((void*)shrink_begin, (unsigned long)shrink_end - (unsigned long)shrink_begin,
                           (unsigned long)shrink_start - (unsigned long)shrink_begin,
                           nullptr, result, nullptr)) {
        return -1;
    }

    ptInject.detach();

    return 0;
}
