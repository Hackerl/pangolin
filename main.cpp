#include "inject/injector.h"
#include <zero/log.h>
#include <zero/cmdline.h>

int main(int argc, char ** argv) {
    INIT_CONSOLE_LOG(zero::INFO);

    zero::CCmdline cmdline;

    cmdline.add({"pid", "process id", zero::value<int>()});

    cmdline.addOptional({"daemon", 'd', "daemon mode", zero::value<bool>(), true});
    cmdline.addOptional({"deaf", '\0', "signal won't be delivered immediately", zero::value<bool>(), true});
    cmdline.addOptional({"environs", 'e', "environment variables", zero::value<std::vector<std::string>>()});

    cmdline.footer("inject argv");
    cmdline.parse(argc, argv);

    int pid = cmdline.get<int>("pid");

    bool daemon = cmdline.getOptional<bool>("daemon");
    bool deaf = cmdline.getOptional<bool>("deaf");

    std::vector<std::string> arguments = cmdline.rest();
    std::vector<std::string> environs = cmdline.getOptional<std::vector<std::string>>("environs");

    if (arguments.empty()) {
        LOG_ERROR("inject empty argv");
        return -1;
    }

    LOG_INFO("exec %s", zero::strings::join(arguments, " ").c_str());

    CInjector injector;

    if (!injector.open(pid, deaf)) {
        LOG_ERROR("process injector open failed");
        return -1;
    }

    return injector.inject(arguments, environs, daemon);
}
