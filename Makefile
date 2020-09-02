FLAGS = -Wall -Wextra -Werror -pedantic -std=c99 -O3
SRC = src

.PHONY: all clean

all: example

example: example.c $(SRC)/blake2cf.o $(SRC)/blake2ets.o
	$(CC) $(FLAGS) -o example example.c $(SRC)/blake2cf.o $(SRC)/blake2ets.o

clean:
	rm -f example *~
