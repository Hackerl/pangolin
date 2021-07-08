#ifndef PANGOLIN_PAYLOAD_H
#define PANGOLIN_PAYLOAD_H

struct CPayload {
    char argument[1024];
    char environ[1024];
    char auxiliary[1024];
    unsigned long arg_count;
    unsigned long env_count;
    unsigned long base_address;
};

#endif //PANGOLIN_PAYLOAD_H
