CC ?= cc
CFLAGS ?= -O -Wall -Wextra -Wformat-security -D_FORTIFY_SOURCE=2
CFLAGS += -std=c99 -D_POSIX_C_SOURCE=200809L
LDFLAGS += -fPIC -shared

# FreeBSD puts the openvpn header in a different location unknown to clang
IPATH_FREEBSD = /usr/local/include/

# Add OS Specific build flags
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),FreeBSD)
	# Add the include path for openvpn-plugin.h
	CFLAGS += -I$(IPATH_FREEBSD) 
	# Ensure the signals we need are visible
	CFLAGS += -D_XOPEN_SOURCE=600
	
	# BSD uses Clang - we need to check for stack-protector-strong flag 
	STACK_PROTECT := $(shell $(CC) --help | grep stack-protector-strong)
	ifneq ($(filter %stack-protector-strong, $(STACK_PROTECT)),)
		CFLAGS += -fstack-protector-strong 
	endif
else
	CFLAGS += -fstack-protector-strong
endif

all: plugin

plugin: auth_script.c
	$(info Building for $(UNAME_S))
	$(CC) $(CFLAGS) $(LDFLAGS) -o auth_script.so auth_script.c

clean:
	rm -f *.o *.so
