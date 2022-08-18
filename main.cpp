#include "inject/injector.h"
#include <zero/log.h>
#include <zero/cmdline.h>

int main(int argc, char ** argv) {
    INIT_CONSOLE_LOG(zero::INFO);

    zero::Cmdline cmdline;

    cmdline.add<int>("pid", "process id");

    cmdline.addOptional("daemon", 'd', "daemon mode");
    cmdline.addOptional("deaf", '\0', "signal won't be delivered immediately");
    cmdline.addOptional<std::vector<std::string>>("environs", 'e', "environment variables");

    cmdline.footer("inject argv");
    cmdline.parse(argc, argv);

    int pid = cmdline.get<int>("pid");

    bool daemon = cmdline.getOptional<bool>("daemon");
    bool deaf = cmdline.getOptional<bool>("deaf");

    auto arguments = cmdline.rest();
    auto environs = cmdline.getOptional<std::vector<std::string>>("environs");

    if (arguments.empty()) {
        LOG_ERROR("inject empty argv");
        return -1;
    }

    LOG_INFO("exec %s", zero::strings::join(arguments, " ").c_str());

    Injector injector;

    if (!injector.open(pid, deaf)) {
        LOG_ERROR("process injector open failed");
        return -1;
    }

    return injector.inject(arguments, environs, daemon);
}
