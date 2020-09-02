FLAGS = -Wall -Wextra -Werror -pedantic -std=c99 -O3

.PHONY: all clean

all: sha256cf.o sha512cf.o blake2cf.o sha256ets.o sha512ets.o blake2ets.o

sha256cf.o: sha256cf.c sha256cf.h
	$(CC) $(FLAGS) -c sha256cf.c

sha512cf.o: sha512cf.c sha512cf.h
	$(CC) $(FLAGS) -c sha512cf.c

blake2cf.o: blake2cf.c blake2cf.h
	$(CC) $(FLAGS) -c blake2cf.c

sha256ets.o: sha256ets.c sha256ets.h memxor.h
	$(CC) $(FLAGS) -c sha256ets.c

sha512ets.o: sha512ets.c sha512ets.h memxor.h
	$(CC) $(FLAGS) -c sha512ets.c

blake2ets.o: blake2ets.c blake2ets.h memxor.h
	$(CC) $(FLAGS) -c blake2ets.c

clean:
	rm -f *.o *~
