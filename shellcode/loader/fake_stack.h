#ifndef PANGOLIN_FAKE_STACK_H
#define PANGOLIN_FAKE_STACK_H

#include <crt_std.h>
#include <crt_log.h>

#define FSTACK_PUSH_STR(sp, s)                  \
{                                               \
    unsigned long l = strlen(s) + 1;            \
    unsigned long a = (unsigned long)sp - l;    \
    while((a % sizeof(unsigned long)) != 0)     \
        a -= 1;                                 \
    memcpy((void*)a, s, l);                     \
    sp = (void*)a;                              \
}

#define FSTACK_PUSH_LONG(sp, n)                 \
{                                               \
    unsigned long l = sizeof(unsigned long);    \
    unsigned long v = n;                        \
    sp -= l;                                    \
    memcpy(sp, &v, l);                          \
}

#define FSTACK_PUSH_AUXV(sp, auxv)              \
{                                               \
    unsigned long * a = auxv;                   \
    FSTACK_PUSH_LONG(sp, 0);                    \
    FSTACK_PUSH_LONG(sp, 0);                    \
    while(*a)                                   \
    {                                           \
        FSTACK_PUSH_LONG(sp, a[1]);             \
        FSTACK_PUSH_LONG(sp, a[0]);             \
        a += 2;                                 \
    }                                           \
}

static inline unsigned char *make_fake_stack(unsigned char *sp, int ac, char **av, char **env, unsigned long *auxv) {
    unsigned char *av_ptr[256] = {};
    unsigned char *env_ptr[256] = {};

    int env_max = 0;

    // align stack
    FSTACK_PUSH_STR(sp, "");

    // copy original env
    while (*env && env_max < 254) {
        FSTACK_PUSH_STR(sp, *env);
        env_ptr[env_max++] = sp;
        env ++;
    }

    // add to envdata
    FSTACK_PUSH_STR(sp, "MANMAP=1");
    env_ptr[env_max++] = sp;

    // argv data
    for (int i = 0; i < ac; i++) {
        FSTACK_PUSH_STR(sp, av[ac - i - 1]);
        av_ptr[i] = sp;
    }

    unsigned char *stack_argument_ptr = sp;

    // auxv
    FSTACK_PUSH_AUXV(sp, auxv);

    // envp
    FSTACK_PUSH_LONG(sp, 0);

    for (int i = 0; i < env_max; i++)
        FSTACK_PUSH_LONG(sp, (unsigned long)env_ptr[i]);

    // argp
    FSTACK_PUSH_LONG(sp, 0);

    for (int i = 0; i < ac; i++)
        FSTACK_PUSH_LONG(sp, (unsigned long)av_ptr[i]);

    // argc
    FSTACK_PUSH_LONG(sp, ac);

    if ((unsigned long)sp % (2 * sizeof(long))) {
        LOG("adjust stack");

        for (unsigned char *i = sp; i < stack_argument_ptr; i++)
            *(i - sizeof(long)) = *i;

        memset(stack_argument_ptr - sizeof(long), 0, sizeof(long));

        sp -= sizeof(long);
    }

    return sp;
}

#endif //PANGOLIN_FAKE_STACK_H
