#ifndef PANGOLIN_LOG_H
#define PANGOLIN_LOG_H

#include <crt_syscall.h>
#include <crt_std.h>

#define NEWLINE     "\n"
#define LOG(message) _write(1, message, strlen(message)); _write(1, NEWLINE, 1);

#endif //PANGOLIN_LOG_H
