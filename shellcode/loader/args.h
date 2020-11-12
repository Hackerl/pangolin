#ifndef PANGOLIN_ARGS_H
#define PANGOLIN_ARGS_H

struct CLoaderArgs {
    int arg_count;
    int env_count;
    unsigned long base_address;
    char arg[1024];
    char env[1024];
    unsigned char aux[1024];
};

#endif //PANGOLIN_ARGS_H
