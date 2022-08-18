#ifndef PANGOLIN_EXECUTOR_H
#define PANGOLIN_EXECUTOR_H

#include "tracee.h"
#include <list>
#include <cstdint>

class Executor : public Tracee {
public:
    explicit Executor(pid_t pid, bool deaf);
    ~Executor();

public:
    std::optional<int> run(void *shellcode, size_t length, uintptr_t base, uintptr_t stack, void *argument);
    std::optional<void *> call(void *shellcode, size_t length, uintptr_t base, uintptr_t stack, void *argument);

private:
    [[nodiscard]] std::optional<uintptr_t> getExecutableMemory() const;

private:
    bool mDeaf;
    std::list<int> mSignals;
};


#endif //PANGOLIN_EXECUTOR_H
