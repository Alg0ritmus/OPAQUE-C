CC=gcc
CFLAGS= -Os -Wall -Werror -Wextra -Wno-unused-function
SRCS := main.c 
SRCS += opaque.c 
SRCS += oprf.c rnd.c
#SRCS += $(wildcard dependencies/*.c)
SRCS += dependencies/sha384-512.c dependencies/sha224-256.c dependencies/hkdf.c dependencies/hmac.c dependencies/usha.c dependencies/sha1.c
SRCS += $(wildcard ristretto255/*.c)

all:
	$(CC) $(CFLAGS) $(SRCS) -o main

