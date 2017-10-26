CC ?= cc
CFLAGS ?= -O -Wall -Wextra -Wformat-security -fstack-protector-strong -D_FORTIFY_SOURCE=2
CFLAGS += -std=c99 -D_POSIX_C_SOURCE=200809L
LDFLAGS += -fPIC -shared

all: plugin

plugin: auth_script.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o auth_script.so auth_script.c

clean:
	rm -f *.o *.so
