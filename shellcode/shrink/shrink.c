#include "shrink.h"
#include <z_memory.h>

void __attribute__ ((visibility ("default"))) shellcode_begin() {

}

void shrink_main(void *ptr) {
    z_free(ptr);
}

void __attribute__ ((visibility ("default"))) shellcode_start() {
    asm volatile("nop; nop; call shrink_main; int3;");
}

void __attribute__ ((visibility ("default"))) shellcode_end() {

}
