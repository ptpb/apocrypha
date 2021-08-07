# paths
PREFIX ?= /usr/local

# includes and libs
LIBS = -lgnutls

# flags
WARNINGS = \
	-Wall -Wextra -Werror \
	-Wno-error=unused-variable \
	-Wno-error=unused-parameter \
	-Wno-override-init \
	-Wshadow \
	-Wformat=2 \
	-Wundef

CFLAGS := -I/usr/include/libressl $(WARNINGS) -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 -Og -g3 $(CFLAGS)
LDFLAGS = -L/usr/lib/libressl -Wl,-rpath=/usr/lib/libressl

# compiler and linker
CC ?= cc
