#include "elf_loader.h"
#include <z_std.h>
#include <z_log.h>

int elf_loader(struct CPayload *payload) {
    int argc = 0;

    char *argv[PAYLOAD_MAX_ARG] = {};
    char *env[PAYLOAD_MAX_ENV] = {};

    if (!z_strlen(payload->argv)) {
        LOG("empty argv");
        return -1;
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

    return 0;
}