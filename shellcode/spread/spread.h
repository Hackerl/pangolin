#ifndef PANGOLIN_SPREAD_H
#define PANGOLIN_SPREAD_H

void __attribute__ ((section (".begin"))) shellcode_begin();
void shellcode_start();
void __attribute__ ((section (".end"))) shellcode_end();

#endif //PANGOLIN_SPREAD_H
