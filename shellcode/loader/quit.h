#ifndef PANGOLIN_QUIT_H
#define PANGOLIN_QUIT_H

#include <sys/user.h>

#ifdef __arm__
typedef struct user_regs regs_t;
typedef struct user_fpregs fp_regs_t;
#elif __aarch64__
typedef struct user_regs_struct regs_t;
typedef struct user_fpsimd_struct fp_regs_t;
#else
typedef struct user_regs_struct regs_t;
typedef struct user_fpregs_struct fp_regs_t;
#endif

typedef struct {
    regs_t regs;
    fp_regs_t fp_regs;
} context_t;

void snapshot(context_t *p);
void quit(int status);
void *quit_p();

#endif //PANGOLIN_QUIT_H
