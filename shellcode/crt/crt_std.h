#ifndef PANGOLIN_CRT_STD_H
#define PANGOLIN_CRT_STD_H

static int strlen(char * str){
    int n = 0;

    while (*str++)
        n++;

    return n;
}

static void memcpy(void *dst, void *src, unsigned int len) {
    unsigned char * d = (unsigned char *) dst;
    unsigned char * s = (unsigned char *) src;

    while (len--)
        *d++ = *s++;
}

static void memset(void * dst, unsigned char c, unsigned int len) {
    unsigned char *p = (unsigned char *)dst;

    while (len--)
        *p++ = c;
}

#endif //PANGOLIN_CRT_STD_H
