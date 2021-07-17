#include "loader.h"
#include <z_log.h>

void __attribute__ ((visibility ("default"))) shellcode_begin() {

}

void loader_main(void *ptr) {
    LOG("elf loader");
}

void __attribute__ ((visibility ("default"))) shellcode_start() {
    asm volatile("nop; nop; call loader_main; int3;");
}

void __attribute__ ((visibility ("default"))) shellcode_end() {

}
