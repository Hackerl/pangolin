#include "loader.h"
#include "payload.h"
#include <z_log.h>
#include <z_syscall.h>
#include <z_std.h>

void __attribute__ ((visibility ("default"))) shellcode_begin() {

}

void loader_main(void *ptr) {
    struct CPayload *payload = (struct CPayload *)ptr;

    int argc = 0;

    char *argv[PAYLOAD_MAX_ARG] = {};
    char *env[PAYLOAD_MAX_ENV] = {};

    if (!z_strlen(payload->argv)) {
        LOG("empty argv");
        z_exit(-1);
    }

    argv[argc++] = payload->argv;

    for (char *i = payload->argv; *i && argc < PAYLOAD_MAX_ARG; i++) {
        if (*i == *PAYLOAD_DELIMITER) {
            *i = 0;
            argv[argc++] = i + 1;
        }
    }

    if (z_strlen(payload->env)) {
        int count = 0;
        env[count++] = payload->env;

        for (char *i = payload->env; *i && count < PAYLOAD_MAX_ENV; i++) {
            if (*i == *PAYLOAD_DELIMITER) {
                *i = 0;
                env[count++] = i + 1;
            }
        }
    }

    for(int i = 0; i < argc; i++)
        LOG("arg[%d] %s", i, argv[i]);

    for(char **e = env; *e != NULL; e++)
        LOG("env %s", *e);

    z_exit(0);
}

void __attribute__ ((visibility ("default"))) shellcode_start() {
    asm volatile("nop; nop; call loader_main; int3;");
}

void __attribute__ ((visibility ("default"))) shellcode_end() {

}
