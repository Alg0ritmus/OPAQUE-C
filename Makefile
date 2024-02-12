CC=gcc
CFLAGS= -Os -Wall -Werror -Wextra -Wno-unused-function
#SRCS := client_app.c 
SRCS += opaque.c 
SRCS += oprf.c rnd.c
#SRCS += $(wildcard dependencies/*.c)
SRCS += dependencies/sha384-512.c dependencies/usha.c dependencies/hkdf.c dependencies/hmac.c
SRCS += $(wildcard ristretto255/*.c)
#SRCS += client_side.c server_side.c

#$(CC) $(CFLAGS) $(SRCS) client.c -o client
#$(CC) $(CFLAGS) $(SRCS) server.c -o server

all: SRCS += main.c 
all:
	$(CC) $(CFLAGS) $(SRCS) -o main

simulation: SRCS += client_side.c server_side.c opaque_in_details/opaque_simulation.c
simulation:
	$(CC) $(CFLAGS) $(SRCS) -o simulation

test: SRCS += test.c
test:
	
	$(CC) $(CFLAGS) $(SRCS) -o test

