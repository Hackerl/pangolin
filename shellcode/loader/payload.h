#ifndef PANGOLIN_PAYLOAD_H
#define PANGOLIN_PAYLOAD_H

#include <stdbool.h>
#include <sys/user.h>

#ifdef __arm__
typedef struct user_regs regs_t;
#else
typedef struct user_regs_struct regs_t;
#endif

#define PAYLOAD_DELIMITER "\1"

#define PAYLOAD_MAX_ARG 256
#define PAYLOAD_MAX_ENV 256

typedef struct {
    bool daemon;
    char argv[1024];
    char env[1024];
    regs_t regs;
} loader_payload_t;

#endif //PANGOLIN_PAYLOAD_H
