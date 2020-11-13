#ifndef PANGOLIN_SHRINK_H
#define PANGOLIN_SHRINK_H

void __attribute__ ((section (".begin"))) shellcode_begin();
void shellcode_start();
void __attribute__ ((section (".end"))) shellcode_end();

#endif //PANGOLIN_SHRINK_H
