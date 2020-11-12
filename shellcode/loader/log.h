#ifndef PANGOLIN_LOG_H
#define PANGOLIN_LOG_H

#include <crt_syscall.h>

#define NEWLINE     "\n"
#define LOG(message) _write(1, message NEWLINE, sizeof(message NEWLINE) - 1);

#endif //PANGOLIN_LOG_H
