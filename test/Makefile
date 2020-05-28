SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)
BIN = $(basename $(OBJ))

all: $(BIN)
	@for test in $(BIN) ; do \
		echo $$test ; \
		./$$test ; \
	done

$(BIN): $(@:=.o)

clean:
	rm -f $(BIN) $(OBJ)

.PHONY: clean all
