#ifndef PANGOLIN_SH_ARGS_H
#define PANGOLIN_SH_ARGS_H

#include <loader/args.h>
#include <string>
#include <vector>

class CShareArgs {
public:
    CShareArgs(int pid, const std::string &file, const std::string &arg, const std::string &env);

public:
    bool getLoaderArgs(CLoaderArgs& loaderArgs);

private:
    bool setAux(unsigned char* buffer, unsigned long size) const;

private:
    unsigned long getBaseAddress() const;

private:
    int mPid;
    std::vector<std::string> mArg;
    std::vector<std::string> mEnv;
};

#endif //PANGOLIN_SH_ARGS_H
