#ifndef PANGOLIN_PAYLOAD_BUILDER_H
#define PANGOLIN_PAYLOAD_BUILDER_H

#include <string>
#include <loader/payload.h>

class CPayloadBuilder {
public:
    explicit CPayloadBuilder(int pid, const std::string &command, const std::string &env, unsigned long base);

public:
    bool build(CPayload &payload);

private:
    bool getBaseAddress(unsigned long& baseAddress) const;
    bool getAuxiliaryVector(char *buffer, unsigned long length) const;

private:
    int mPID;
    unsigned long mBase;

private:
    std::string mCommand;
    std::string mEnv;
};


#endif //PANGOLIN_PAYLOAD_BUILDER_H
