#ifndef PANGOLIN_CRT_STD_H
#define PANGOLIN_CRT_STD_H

inline int strlen(char * str){
    int n = 0;

    while (*str++)
        n++;

    return n;
}

inline void memcpy(void *dst, void *src, unsigned int len) {
    unsigned char * d = (unsigned char *) dst;
    unsigned char * s = (unsigned char *) src;

    while (len--)
        *d++ = *s++;
}

#endif //PANGOLIN_CRT_STD_H
