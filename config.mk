# paths
PREFIX ?= /usr/local

# includes and libs
LIBS = -ltls -lcrypto

# flags
WARNINGS = \
	-Wall -Wextra -Werror \
	-Wno-error=unused-variable \
	-Wshadow \
	-Wformat=2 \
	-Wundef

CFLAGS := -I/usr/include/libressl $(WARNINGS) -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 -Og -g3 $(CFLAGS)
LDFLAGS = -L/usr/lib/libressl -Wl,-rpath=/usr/lib/libressl $(LIBS)

# compiler and linker
CC ?= cc
