#ifndef PANGOLIN_LOG_H
#define PANGOLIN_LOG_H

#include "printf.h"
#include <crt_syscall.h>

#define LINE_PS     "> "
#define NEWLINE     "\n"

void _putchar(char character) {
    _write(1, &character, 1);
}

#define LOG(message, args...) printf(LINE_PS message NEWLINE, ## args)

#endif //PANGOLIN_LOG_H
