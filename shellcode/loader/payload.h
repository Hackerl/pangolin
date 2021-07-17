#ifndef PANGOLIN_PAYLOAD_H
#define PANGOLIN_PAYLOAD_H

#define PAYLOAD_DELIMITER "\1"

#define PAYLOAD_MAX_ARG 256
#define PAYLOAD_MAX_ENV 256

struct CPayload {
    int daemon;
    char argv[1024];
    char env[1024];
};

#endif //PANGOLIN_PAYLOAD_H
