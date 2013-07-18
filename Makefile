CC=/usr/bin/gcc
CFLAGS=-std=gnu99 -Wall -Wextra -pedantic -Os

all: revsh

revsh: revsh.c
	$(CC) $(CFLAGS) -o revsh revsh.c

clean:
	rm revsh
