#ifndef PANGOLIN_PAYLOAD_BUILDER_H
#define PANGOLIN_PAYLOAD_BUILDER_H

#include <string>
#include <loader/payload.h>

class CPayloadBuilder {
public:
    explicit CPayloadBuilder(int pid, const std::string &commandline, const std::string &environs, unsigned long baseAddress);

public:
    bool build(CPayload &payload);

private:
    bool getBaseAddress(unsigned long& baseAddress) const;
    bool getAuxiliaryVector(char *buffer, unsigned long length) const;

private:
    int mPID;
    unsigned long mBaseAddress;

private:
    std::string mCommandline;
    std::string mEnvirons;
};


#endif //PANGOLIN_PAYLOAD_BUILDER_H
