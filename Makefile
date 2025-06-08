CC = gcc
CFLAGS = -Wall -std=c99 -g
LDFLAGS = -lpthread -lmta_crypt
SRC = main.c encrypter.c decrypter.c
OBJ = $(SRC:.c=.o)
TARGET = mta_crypto

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c shared_data.h encrypter.h decrypter.h log_utils.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJ) $(TARGET)

