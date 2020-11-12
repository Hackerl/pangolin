#ifndef PANGOLIN_LOADER_H
#define PANGOLIN_LOADER_H

extern "C" {
void *loader_begin();
void loader_self(void *ptr);
void loader_start();
void *loader_end();
};

#endif //PANGOLIN_LOADER_H
