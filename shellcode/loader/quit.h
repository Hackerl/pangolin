#ifndef PANGOLIN_QUIT_H
#define PANGOLIN_QUIT_H

#include <sys/user.h>

#ifdef __arm__
typedef struct user_regs regs_t;
#else
typedef struct user_regs_struct regs_t;
#endif

void snapshot(regs_t *regs);
void quit(int status);

#endif //PANGOLIN_QUIT_H
