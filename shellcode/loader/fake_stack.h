#ifndef PANGOLIN_FAKE_STACK_H
#define PANGOLIN_FAKE_STACK_H

#include <crt_std.h>
#include <crt_log.h>

#define FAKE_STACK_PUSH_STR(sp, s)              \
{                                               \
    unsigned long l = strlen(s) + 1;            \
    unsigned long a = (unsigned long)sp - l;    \
                                                \
    while((a % sizeof(unsigned long)) != 0)     \
        a -= 1;                                 \
                                                \
    memcpy((void*)a, s, l);                     \
    sp = (void*)a;                              \
}

#define FAKE_STACK_PUSH_LONG(sp, n)             \
{                                               \
    unsigned long l = sizeof(unsigned long);    \
    unsigned long v = n;                        \
    sp -= l;                                    \
    memcpy(sp, &v, l);                          \
}

#define FAKE_STACK_PUSH_AUXV(sp, auxv)          \
{                                               \
    unsigned long *a = auxv;                    \
                                                \
    FAKE_STACK_PUSH_LONG(sp, 0);                \
    FAKE_STACK_PUSH_LONG(sp, 0);                \
                                                \
    while(*a) {                                 \
        FAKE_STACK_PUSH_LONG(sp, a[1]);         \
        FAKE_STACK_PUSH_LONG(sp, a[0]);         \
        a += 2;                                 \
    }                                           \
}

static inline unsigned char *make_fake_stack(unsigned char *sp, unsigned long argc, char **argv, char **env, unsigned long *auxiliary_vector) {
    unsigned char *av_ptr[256] = {};
    unsigned char *env_ptr[256] = {};

    unsigned long env_max = 0;

    // align stack
    FAKE_STACK_PUSH_STR(sp, "")

    // copy original environ
    while (*env && env_max < 254) {
        FAKE_STACK_PUSH_STR(sp, *env)
        env_ptr[env_max++] = sp;
        env ++;
    }

    // pangolin env
    FAKE_STACK_PUSH_STR(sp, "PANGOLIN=1")
    env_ptr[env_max++] = sp;

    // argv data
    for (unsigned long i = 0; i < argc; i++) {
        FAKE_STACK_PUSH_STR(sp, argv[argc - i - 1])
        av_ptr[i] = sp;
    }

    unsigned char *stack_argument_ptr = sp;

    // auxiliary vector
    FAKE_STACK_PUSH_AUXV(sp, auxiliary_vector)

    // env ptr
    FAKE_STACK_PUSH_LONG(sp, 0)

    for (int i = 0; i < env_max; i++)
        FAKE_STACK_PUSH_LONG(sp, (unsigned long)env_ptr[i])

    // arg ptr
    FAKE_STACK_PUSH_LONG(sp, 0)

    for (int i = 0; i < argc; i++)
        FAKE_STACK_PUSH_LONG(sp, (unsigned long)av_ptr[i])

    // argc
    FAKE_STACK_PUSH_LONG(sp, argc)

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
