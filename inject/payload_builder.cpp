#include "payload_builder.h"
#include <common/log.h>
#include <common/utils/shell.h>
#include <common/utils/process.h>

CPayloadBuilder::CPayloadBuilder(int pid, const std::string &command, const std::string &env, unsigned long base) {
    mPID = pid;
    mCommand = command;
    mEnv = env;
    mBase = base;
}

bool CPayloadBuilder::build(CPayload &payload) {
    std::list<std::string> args;
    std::list<std::string> envs;

    if (!CShellAPI::expansion(mCommand, args) || !CShellAPI::expansion(mEnv, envs)) {
        LOG_ERROR("shell expansion failed");
        return false;
    }

    payload.arg_count = args.size();
    payload.env_count = envs.size();

    char *arg = payload.arg;
    char *env = payload.env;

    for (const auto& a: args) {
        strcpy(arg, a.c_str());
        arg += a.length() + 1;
    }

    for (const auto& e: envs) {
        strcpy(env, e.c_str());
        env += e.length() + 1;
    }

    if (!getAuxiliaryVector(payload.auxv, sizeof(payload.auxv))) {
        LOG_ERROR("get auxiliary vector failed");
        return false;
    }

    if (mBase != 0) {
        payload.base_address = mBase;
        return true;
    }

    if (!getBaseAddress(mBase)) {
        LOG_ERROR("find base address failed");
        return false;
    }

    payload.base_address = mBase;

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
