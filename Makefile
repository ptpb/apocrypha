include config.mk

SRC = main.c native.c http.c
OBJ = ${SRC:.c=.o}

.c.o:
	@echo CC -c $<
	@${CC} -c ${CFLAGS} $<

pb3: ${OBJ}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ} ${LDFLAGS}

clean:
	rm -f pb3 ${OBJ}
