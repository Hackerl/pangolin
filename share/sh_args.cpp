#include "sh_args.h"
#include <common/utils/string_helper.h>
#include <cstring>
#include <common/utils/process.h>
#include <common/log.h>

CShareArgs::CShareArgs(int pid, const std::string &file, const std::string &arg, const std::string &env) {
    mPid = pid;

    mArg = CStringHelper::split(arg, ' ');
    mEnv = CStringHelper::split(env, ' ');

    mArg.insert(mArg.begin(), file);
}

bool CShareArgs::getLoaderArgs(CLoaderArgs &loaderArgs) {
    loaderArgs.arg_count = mArg.size();
    loaderArgs.env_count = mEnv.size();

    char *arg = loaderArgs.arg;
    char *env = loaderArgs.env;

    for (const auto& a: mArg) {
        strcpy(arg, a.c_str());
        arg += a.length() + 1;
    }

    for (const auto& e: mEnv) {
        strcpy(env, e.c_str());
        env += e.length() + 1;
    }

    if (!loaderArgs.base_address)
        loaderArgs.base_address = getBaseAddress();

    if (!loaderArgs.base_address) {
        LOG_ERROR("find base address failed");
        return false;
    }

    if (!setAux(loaderArgs.auxv, sizeof(loaderArgs.auxv))) {
        LOG_ERROR("read auxv failed");
        return false;
    }

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

        baseAddress = m.end + 0x1000000 - (m.end % 0x1000000);
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
