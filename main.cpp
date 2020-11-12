#include "inject/pt_inject.h"
#include <spread/spread.h>
#include <shrink/shrink.h>
#include <loader/loader.h>
#include <common/cmdline.h>
#include <common/log.h>

int main(int argc, char ** argv) {
    cmdline::parser parse;

    parse.add<int>("pid", 'p', "pid", true, 0);
    parse.add<std::string>("file", 'f', "inject file", true, "");

    parse.parse_check(argc, argv);

    int pid = parse.get<int>("pid");
    std::string injectFile = parse.get<std::string>("file");

    LOG_INFO("inject %s to %d", injectFile.c_str(), pid);

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

    auto base = (unsigned long)result + PAGE_SIZE - (unsigned long)result % PAGE_SIZE;

    if (!ptInject.runCode((void*)loader_begin(), (unsigned long)loader_end() - (unsigned long)loader_begin(),
                           (unsigned long)loader_start - (unsigned long)loader_begin(),
                           (void *)base, nullptr)) {
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
