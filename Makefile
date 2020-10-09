include config.mk

DEP = $(wildcard *.h)
SRC = main.c native.c http.c hex.c token.c storage.c base75.c
OBJ = $(SRC:.c=.o)
NAME = apocrypha

all: $(NAME)

%.o: %.c $(DEP)
	@echo CC -c $<
	@$(CC) -c $(CFLAGS) $<

$(NAME): $(OBJ)
	@echo CC -o $@
	@$(CC) -o $@ $(OBJ) $(LDFLAGS)

clean:
	rm -f $(NAME) $(OBJ)

gencert:
	openssl req -new \
		-newkey rsa:2048 -nodes -keyout key.pem \
		-x509 -out cert.pem -subj '/CN=localhost.localdomain'

.PHONY: clean all gencert
