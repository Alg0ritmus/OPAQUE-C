CC=gcc
CFLAGS= -Os -Wall -Werror -Wextra -Wno-unused-function
#SRCS := main.c 
#SRCS := client_app.c 
SRCS += opaque.c 
SRCS += oprf.c rnd.c
#SRCS += $(wildcard dependencies/*.c)
SRCS += dependencies/sha384-512.c dependencies/sha224-256.c dependencies/hkdf.c dependencies/hmac.c dependencies/usha.c dependencies/sha1.c
SRCS += $(wildcard ristretto255/*.c)
SRCS += client_side.c server_side.c

all:
	#$(CC) $(CFLAGS) $(SRCS) -o main
	$(CC) $(CFLAGS) $(SRCS) client.c -o client
	$(CC) $(CFLAGS) $(SRCS) server.c -o server

