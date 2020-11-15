CFLAGS 	+= -D_GNU_SOURCE -std=gnu99
CFLAGS 	+= -static-libgcc -lgcc
CFLAGS 	+= -I crt
CFLAGS  += -shared -fvisibility=hidden -nostdlib
CFLAGS  += -Os -fdata-sections -ffunction-sections
CFLAGS 	+= -fno-common -fno-stack-protector -fomit-frame-pointer -fno-exceptions -fno-asynchronous-unwind-tables -fno-unwind-tables
LDFLAGS += -T linker.ld -Wl,--gc-sections
PORTABLE = -fPIC -fno-builtin

all:
	$(CC) $(CFLAGS) $(PORTABLE) $(LDFLAGS) -o libspread.so spread/spread.c
	$(CC) $(CFLAGS) $(PORTABLE) $(LDFLAGS) -o libshrink.so shrink/shrink.c
	$(CC) $(CFLAGS) $(PORTABLE) $(LDFLAGS) -o libloader.so loader/loader.c crt/printf/printf.c

clean:
	rm libspread.so libshrink.so libloader.so