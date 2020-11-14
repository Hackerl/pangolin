#ifndef PANGOLIN_SH_ARGS_H
#define PANGOLIN_SH_ARGS_H

#include <loader/args.h>
#include <string>
#include <vector>
#include <list>

class CShareArgs {
public:
    CShareArgs(int pid, const std::string &command, const std::string &env);

public:
    bool getLoaderArgs(CLoaderArgs& loaderArgs);

private:
    bool setAux(CLoaderArgs &loaderArgs) const;

private:
    bool getBaseAddress(unsigned long& baseAddress) const;

private:
    static bool wordExp(const std::string &str, std::list<std::string>& words);

private:
    int mPid;
    std::list<std::string> mArg;
    std::list<std::string> mEnv;
};

#endif //PANGOLIN_SH_ARGS_H
