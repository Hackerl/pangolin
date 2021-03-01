#ifndef PANGOLIN_PAYLOAD_H
#define PANGOLIN_PAYLOAD_H

struct CPayload {
    int arg_count;
    int env_count;
    unsigned long base_address;
    char arg[1024];
    char env[1024];
    char auxv[1024];
};

#endif //PANGOLIN_PAYLOAD_H
