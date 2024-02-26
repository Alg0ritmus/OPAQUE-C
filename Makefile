CC=gcc
CFLAGS= -Os -Wall -Werror -Wextra --pedantic-errors
SRCS += opaque.c 
SRCS += oprf.c
SRCS += dependencies/sha384-512.c dependencies/usha.c dependencies/hkdf.c dependencies/hmac.c
SRCS += $(wildcard ristretto255/*.c)

test: SRCS += test.c
test:
	
	$(CC) $(CFLAGS) $(SRCS) -o test

