# paths
PREFIX = /usr/local

# includes and libs
LIBS = -ltls -lcrypto

# flags
CFLAGS = -I/usr/include/libressl -Wall -Werror -Wno-error=unused-variable -D_GNU_SOURCE -g
LDFLAGS = -L/usr/lib/libressl -Wl,-rpath=/usr/lib/libressl ${LIBS}

# compiler and linker
CC = cc
