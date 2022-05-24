#ifndef PANGOLIN_INJECTOR_H
#define PANGOLIN_INJECTOR_H

#include <ptrace/executor.h>
#include <list>
#include <vector>
#include <string>

class CInjector {
public:
    ~CInjector();

public:
    bool open(pid_t pid, bool deaf);

public:
    int inject(const std::vector<std::string>& arguments, const std::vector<std::string>& environs, bool daemon);

private:
    std::list<CExecutor *> mExecutors;
};


#endif //PANGOLIN_INJECTOR_H
