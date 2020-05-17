include config.mk

DEP = $(wildcard *.h)
SRC = main.c native.c http.c hex.c
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

.PHONY: clean all
