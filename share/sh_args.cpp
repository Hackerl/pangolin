#include "sh_args.h"
#include <common/utils/string_helper.h>
#include <cstring>
#include <common/utils/process.h>
#include <common/log.h>
#include <unistd.h>

CShareArgs::CShareArgs(int pid, const std::string& arg, const std::string& env) {
    mPid = pid ? pid : getpid();
    mArgument = CStringHelper::split(arg, ' ');
    mEnvironment = CStringHelper::split(env, ' ');
}

bool CShareArgs::getLoaderArgs(CLoaderArgs &loaderArgs) {
    loaderArgs.arg_count = mArgument.size();
    loaderArgs.env_count = mEnvironment.size();

    char *arg = loaderArgs.arg;
    char *env = loaderArgs.env;

    for (const auto& a: mArgument) {
        strcpy(arg, a.c_str());
        arg += a.length() + 1;
    }

    for (const auto& e: mEnvironment) {
        strcpy(env, e.c_str());
        env += e.length() + 1;
    }

    loaderArgs.base_address = getBaseAddress();

    if (!loaderArgs.base_address)
        return false;

    if (!setAux(loaderArgs.aux, sizeof(loaderArgs.aux)))
        return false;

    return true;
}

unsigned long CShareArgs::getBaseAddress() const {
    std::list<CProcessMap> processMaps;

    if (!CProcess::getProcessMaps(mPid, processMaps)) {
        LOG_ERROR("get process maps failed");
        return -1;
    }

    unsigned long baseAddress = 0;

    for (const auto& m: processMaps) {
        if (m.start > 0x7f0000000000)
            break;

        baseAddress = m.end + 0x01000000 - (m.end % 0x01000000);
    }

    return baseAddress;
}

bool CShareArgs::setAux(unsigned char* buffer, unsigned long size) const {
    std::string auxPath = "/proc/" + std::to_string(mPid) + "/auxv";
    std::ifstream infile(auxPath, std::ifstream::binary);

    if (!infile.is_open())
        return false;

    infile.read((char *)buffer, size);

    return true;
}
