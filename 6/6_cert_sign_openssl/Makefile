TARGET=sign_test
CPPFLAGS=
CFLAGS=-O0 -g -Wall -D_GNU_SOURCE
LDLIBS=-lcrypto -lssl
CC=gcc

SOURCES=$(wildcard *.c)
OBJECTS=$(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LDLIBS)

clean:
	rm -f *.o *~ core signed_and_encrypted_file.txt $(TARGET)

.PHONY: clean
