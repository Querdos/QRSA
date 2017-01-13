CC=gcc
CFLAGS=-DDEBUG -g -lgmp -I.
DEPS = rsa.h rsa_keys.h
OBJ = rsa_keys.o rsa.o main.o 

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

rsa: $(OBJ)
	gcc -o $@ $^ $(CFLAGS)
