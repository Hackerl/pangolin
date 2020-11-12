#ifndef PANGOLIN_LOG_H
#define PANGOLIN_LOG_H

#include <crt_syscall.h>
#include <crt_std.h>

#define LINE_PS     "> "
#define NEWLINE     "\n"

#define LOG(message) _write(1, LINE_PS message NEWLINE, sizeof(LINE_PS message NEWLINE) - 1);

#endif //PANGOLIN_LOG_H
