include config.mk

SRC = main.c native.c http.c hex.c
OBJ = ${SRC:.c=.o}
NAME = apocrypha

.c.o:
	@echo CC -c $<
	@${CC} -c ${CFLAGS} $<

${NAME}: ${OBJ}
	@echo CC -o $@
	@${CC} -o $@ ${OBJ} ${LDFLAGS}

clean:
	rm -f ${NAME} ${OBJ}
