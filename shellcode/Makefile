CFLAGS 	+= -D_GNU_SOURCE -std=gnu99
CFLAGS 	+= -I c-runtime/include -I c-runtime/printf
CFLAGS  += -shared -fvisibility=hidden
CFLAGS  += -Os -fdata-sections -ffunction-sections
CFLAGS 	+= -fno-common -fno-stack-protector -fomit-frame-pointer -fno-exceptions -fno-asynchronous-unwind-tables -fno-unwind-tables
CFLAGS	+= -D DISABLE_CACHE
LDFLAGS += -T linker.ld -Wl,--gc-sections -Wl,--no-undefined
PORTABLE = -fPIC -fno-builtin

MACHINE	= $(shell uname -m)

all: $(MACHINE)
	objcopy -O binary --only-section=.text liballoc.so alloc.sc
	objcopy -O binary --only-section=.text libfree.so free.sc
	objcopy -O binary --only-section=.text libloader.so loader.sc
	xxd -i alloc.sc > alloc.h
	xxd -i free.sc > free.h
	xxd -i loader.sc > loader.h


i386: x86
i486: x86
i686: x86
x86:
	$(CC) $(CFLAGS) $(PORTABLE) $(LDFLAGS) -m32 -nostdlib -o liballoc.so alloc/entry.c c-runtime/src/*.c
	$(CC) $(CFLAGS) $(PORTABLE) $(LDFLAGS) -m32 -nostdlib -o libfree.so free/entry.c c-runtime/src/*.c
	$(CC) $(CFLAGS) $(PORTABLE) $(LDFLAGS) -m32 -nostdlib -o libloader.so loader/entry.c loader/quit.c loader/elf_loader.c c-runtime/src/*.c c-runtime/printf/printf.c -static-libgcc -lgcc


amd64: x86_64
x86_64:
	$(CC) $(CFLAGS) $(PORTABLE) $(LDFLAGS) -nostdlib -o liballoc.so alloc/entry.c c-runtime/src/*.c
	$(CC) $(CFLAGS) $(PORTABLE) $(LDFLAGS) -nostdlib -o libfree.so free/entry.c c-runtime/src/*.c
	$(CC) $(CFLAGS) $(PORTABLE) $(LDFLAGS) -nostdlib -o libloader.so loader/entry.c loader/quit.c loader/elf_loader.c c-runtime/src/*.c c-runtime/printf/printf.c


arm: armv7l
armhf: armv7l
armv7: armv7l
armv7l:
	$(CC) $(CFLAGS) $(PORTABLE) $(LDFLAGS) -nostartfiles -o liballoc.so alloc/entry.c c-runtime/src/*.c
	$(CC) $(CFLAGS) $(PORTABLE) $(LDFLAGS) -nostartfiles -o libfree.so free/entry.c c-runtime/src/*.c
	$(CC) $(CFLAGS) $(PORTABLE) $(LDFLAGS) -nostartfiles -o libloader.so loader/entry.c loader/quit.c loader/elf_loader.c c-runtime/src/*.c c-runtime/printf/printf.c


arm64: aarch64
armv8: aarch64
armv8l: aarch64
aarch64:
	$(CC) $(CFLAGS) $(PORTABLE) $(LDFLAGS) -nostdlib -o liballoc.so alloc/entry.c c-runtime/src/*.c
	$(CC) $(CFLAGS) $(PORTABLE) $(LDFLAGS) -nostdlib -o libfree.so free/entry.c c-runtime/src/*.c
	$(CC) $(CFLAGS) $(PORTABLE) $(LDFLAGS) -nostdlib -o libloader.so loader/entry.c loader/quit.c loader/elf_loader.c c-runtime/src/*.c c-runtime/printf/printf.c


clean:
	rm liballoc.so libfree.so libloader.so