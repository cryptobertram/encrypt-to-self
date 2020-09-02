FLAGS = -Wall -Wextra -Werror -pedantic -std=c99 -O3
SRC = ../src

.PHONY: all clean

all: sha256cf_selftest sha512cf_selftest blake2cf_selftest ets_selftest

sha256cf_selftest: sha256cf_selftest.c $(SRC)/sha256cf.o
	$(CC) $(FLAGS) -o sha256cf_selftest sha256cf_selftest.c $(SRC)/sha256cf.o

sha512cf_selftest: sha512cf_selftest.c $(SRC)/sha512cf.o
	$(CC) $(FLAGS) -o sha512cf_selftest sha512cf_selftest.c $(SRC)/sha512cf.o

blake2cf_selftest: blake2cf_selftest.c $(SRC)/blake2cf.o
	$(CC) $(FLAGS) -o blake2cf_selftest blake2cf_selftest.c $(SRC)/blake2cf.o

ets_selftest: ets_selftest.c $(SRC)/sha256cf.o $(SRC)/sha512cf.o $(SRC)/blake2cf.o $(SRC)/sha256ets.o $(SRC)/sha512ets.o $(SRC)/blake2ets.o
	$(CC) $(FLAGS) -o ets_selftest ets_selftest.c $(SRC)/sha256cf.o $(SRC)/sha512cf.o $(SRC)/blake2cf.o $(SRC)/sha256ets.o $(SRC)/sha512ets.o $(SRC)/blake2ets.o

clean:
	rm -f *_selftest *~
