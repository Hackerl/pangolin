#ifndef PANGOLIN_EXECUTOR_H
#define PANGOLIN_EXECUTOR_H

#include "tracee.h"
#include <list>

class CExecutor : public CTracee {
public:
    explicit CExecutor(pid_t pid, bool deaf);
    ~CExecutor();

public:
    bool run(const unsigned char *shellcode, unsigned int length, void *base, void *stack, void *argument, int &status);
    bool call(const unsigned char *shellcode, unsigned int length, void *base, void *stack, void *argument, void **result);

private:
    bool getExecBase(void **base) const;

private:
    bool mDeaf;
    std::list<int> mSignals;
};


#endif //PANGOLIN_EXECUTOR_H
