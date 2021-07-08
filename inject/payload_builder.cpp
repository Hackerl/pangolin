#include "payload_builder.h"
#include <common/log.h>
#include <common/utils/shell.h>
#include <common/utils/process.h>

CPayloadBuilder::CPayloadBuilder(int pid, const std::string &commandline, const std::string &environs, unsigned long baseAddress) {
    mPID = pid;
    mCommandline = commandline;
    mEnvirons = environs;
    mBaseAddress = baseAddress;
}

bool CPayloadBuilder::build(CPayload &payload) {
    std::list<std::string> arguments;
    std::list<std::string> environs;

    if (!CShellAPI::expansion(mCommandline, arguments) || !CShellAPI::expansion(mEnvirons, environs)) {
        LOG_ERROR("shell expansion failed");
        return false;
    }

    payload.arg_count = arguments.size();
    payload.env_count = environs.size();

    char *arg = payload.argument;
    char *env = payload.environ;

    for (const auto &i: arguments) {
        strcpy(arg, i.c_str());
        arg += i.length() + 1;
    }

    for (const auto &i: environs) {
        strcpy(env, i.c_str());
        env += i.length() + 1;
    }

    if (!getAuxiliaryVector(payload.auxiliary, sizeof(payload.auxiliary))) {
        LOG_ERROR("get auxiliary vector failed");
        return false;
    }

    if (mBaseAddress != 0) {
        payload.base_address = mBaseAddress;
        return true;
    }

    if (!getBaseAddress(mBaseAddress)) {
        LOG_ERROR("find base address failed");
        return false;
    }

    payload.base_address = mBaseAddress;

    return true;
}

bool CPayloadBuilder::getBaseAddress(unsigned long &baseAddress) const {
    std::list<CProcessMap> processMaps;

    if (!CProcess::getProcessMaps(mPID, processMaps)) {
        LOG_ERROR("get process maps failed");
        return false;
    }

    baseAddress = 0;

    for (const auto& m: processMaps) {
        if (m.start > 0x7f0000000000)
            break;

        baseAddress = m.end;
    }

    baseAddress += 0x1000000 - (baseAddress % 0x1000000);

    return true;
}

bool CPayloadBuilder::getAuxiliaryVector(char *buffer, unsigned long length) const {
    std::string path = CPath::join("/proc", std::to_string(mPID), "auxv");
    std::ifstream ifs(path);

    if (!ifs.is_open()) {
        LOG_ERROR("open file failed: %s", path.c_str());
        return false;
    }

    ifs.read(buffer, length);

    return true;
}
