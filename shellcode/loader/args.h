#ifndef PANGOLIN_ARGS_H
#define PANGOLIN_ARGS_H

struct CLoaderArgs {
    unsigned long size;
    int arg_count;
    int env_count;
    unsigned long base_address;
    char data[];
};

#endif //PANGOLIN_ARGS_H
