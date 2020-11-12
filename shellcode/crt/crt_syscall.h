#ifndef PANGOLIN_CRT_SYSCALL_H
#define PANGOLIN_CRT_SYSCALL_H

#include <syscall.h>
#include <sys/types.h>

// ========================================================================== //
// define syscall asm stub for all archs here
// ========================================================================== //

// x86
#ifdef __i386__
#define _syscall_do(sys_nbr, ret_type)                                      \
    {                                                                       \
        ret_type ret = 0;                                                   \
        register int r0 asm ("ebx") = (int)a1;                              \
        register int r1 asm ("ecx") = (int)a2;                              \
        register int r2 asm ("edx") = (int)a3;                              \
        register int r3 asm ("esi") = (int)a4;                              \
        register int r4 asm ("edi") = (int)a5;                              \
        register int r5 asm ("ebp") = (int)a6;                              \
        register int r7 asm ("eax") = sys_nbr;                              \
        asm volatile                                                        \
        (                                                                   \
            "int $0x80;"                                                    \
            : "=r" (ret)                                                    \
            : "r"(r7), "r"(r0), "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5) \
        );                                                                  \
        return ret;                                                         \
    }

// x86_64 aka amd64
#elif __x86_64__
#define _syscall_do(sys_nbr, ret_type)                                      \
    {                                                                       \
        register long r10 asm("r10") = (long)a4;                            \
        register long r8  asm("r8")  = (long)a5;                            \
        register long r9  asm("r9")  = (long)a6;                            \
        ret_type ret = 0;                                                   \
        asm volatile                                                        \
        (                                                                   \
            "syscall"                                                       \
            : "=a" (ret)                                                    \
            : "0"(sys_nbr), "D"(a1),  "S"(a2),                              \
              "d"(a3),      "r"(r10), "r"(r8), "r"(r9)                      \
            : "cc", "rcx", "r11", "memory"                                  \
        );                                                                  \
        return ret;                                                         \
    }


// arm
#elif __arm__
#define _syscall_do(sys_nbr, ret_type)                                      \
    {                                                                       \
        ret_type ret = 0;                                                   \
        register int r0 asm ("r0") = (int)a1;                               \
        register int r1 asm ("r1") = (int)a2;                               \
        register int r2 asm ("r2") = (int)a3;                               \
        register int r3 asm ("r3") = (int)a4;                               \
        register int r4 asm ("r4") = (int)a5;                               \
        register int r5 asm ("r5") = (int)a6;                               \
        register int r7 asm ("r7") = sys_nbr;                               \
        asm volatile                                                        \
        (                                                                   \
            "swi #0; mov %0, r0"                                            \
            : "=r" (ret)                                                    \
            : "r"(r7), "r"(r0), "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5) \
        );                                                                  \
        return ret;                                                         \
    }


// arm64
#elif __aarch64__
    #define _syscall_do(sys_nbr, ret_type)                                  \
    {                                                                       \
        ret_type ret = 0;                                                   \
        register long x0 asm ("x0") = (long)a1;                             \
        register long x1 asm ("x1") = (long)a2;                             \
        register long x2 asm ("x2") = (long)a3;                             \
        register long x3 asm ("x3") = (long)a4;                             \
        register long x4 asm ("x4") = (long)a5;                             \
        register long x5 asm ("x5") = (long)a6;                             \
        register long x8 asm ("x8") = sys_nbr;                              \
        asm volatile                                                        \
        (                                                                   \
            "svc #0; mov %0, x0"                                            \
            : "=r" (ret)                                                    \
            : "r"(x8), "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) \
        );                                                                  \
        return ret;                                                         \
    }

// something else?
#else
    #error "unknown arch"
#endif


// ========================================================================== //
// defines to generate syscall wrappers
// ========================================================================== //

#define _syscall6(sys_nbr, sys_name, ret_type, t1, t2, t3, t4, t5, t6)      \
static inline ret_type sys_name(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5, t6 a6)   \
{                                                                           \
    _syscall_do(sys_nbr, ret_type)                                          \
}

#define _syscall5(sys_nbr, sys_name, ret_type, t1, t2, t3, t4, t5)          \
static inline ret_type sys_name(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5)          \
{                                                                           \
    long a6=0;                                                              \
    _syscall_do(sys_nbr, ret_type)                                          \
}

#define _syscall4(sys_nbr, sys_name, ret_type, t1, t2, t3, t4)              \
static inline ret_type sys_name(t1 a1, t2 a2, t3 a3, t4 a4)                 \
{                                                                           \
    long a6=0, a5=0;                                                        \
    _syscall_do(sys_nbr, ret_type)                                          \
}

#define _syscall3(sys_nbr, sys_name, ret_type, t1, t2, t3)                  \
static inline ret_type sys_name(t1 a1, t2 a2, t3 a3)                        \
{                                                                           \
    long a6=0, a5=0, a4=0;                                                  \
    _syscall_do(sys_nbr, ret_type)                                          \
}

#define _syscall2(sys_nbr, sys_name, ret_type, t1, t2)                      \
static inline ret_type sys_name(t1 a1, t2 a2)                               \
{                                                                           \
    long a6=0, a5=0, a4=0, a3=0;                                            \
    _syscall_do(sys_nbr, ret_type)                                          \
}

#define _syscall1(sys_nbr, sys_name, ret_type, t1)                          \
static inline ret_type sys_name(t1 a1)                                      \
{                                                                           \
    long a6=0, a5=0, a4=0, a3=0, a2=0;                                      \
    _syscall_do(sys_nbr, ret_type)                                          \
}

#define _syscall0(sys_nbr, sys_name, ret_type)                              \
static inline ret_type sys_name(void)                                       \
{                                                                           \
    long a6=0, a5=0, a4=0, a3=0, a2=0, a1=0;                                \
    _syscall_do(sys_nbr, ret_type)                                          \
}


// ========================================================================== //
// define desired syscall
// ========================================================================== //

_syscall0(SYS_getpid,   _getpid,    int)

_syscall1(SYS_exit,     __exit,     int,        int)

_syscall1(SYS_close,    _close,     int,        int)
_syscall1(SYS_brk,      _brk,       long,       unsigned long)

_syscall2(SYS_munmap,   _munmap,    long,       char*, int)

_syscall3(SYS_read,     _read,      ssize_t,    int, void *, size_t)
_syscall3(SYS_write,    _write,     ssize_t,    int, const void *, size_t)
_syscall3(SYS_lseek,    _lseek,     long,       int, long, int)
_syscall3(SYS_mprotect, _mprotect,  long,       void*, long, int)

#if __i386__ || __arm__ || __x86_64__
_syscall3(SYS_open,     _open,      int,        char *, int, int)
#else
_syscall4(SYS_openat,   _openat,    int,        int, char *, int, int)
#define AT_FDCWD        -100
#define _open(a, b, c) _openat(AT_FDCWD, a, b, c)
#endif

_syscall4(SYS_ptrace,   _ptrace,    long,       int, int, void*, void*)
_syscall4(SYS_wait4,    _wait4,     int,        int, int*, int, void*)

#if __i386__ || __arm__
_syscall6(SYS_mmap2, _mmap, void *, void *, long, int, int, int, long)
#else
_syscall6(SYS_mmap, _mmap, void *, void *, long, int, int, int, long)
#endif

#endif //PANGOLIN_CRT_SYSCALL_H
