#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>


// OPAQUE

/**
  * MSG idea:
  * #--------#---------#
  * | header | payload |
  * #--------#---------#
**/


/** message header-type table
  * #--code--#----size----#-----------msg type-----------------
  * |  0x00  |     0B     |  reserved
  * |  0x01  |    32B     |  ClientRegistrationRequest
  * |  0x02  |    64B     |  ServerRegistrationResponse
  * |  0x03  |   192B     |  ClientRegistrationRecord
  * |  0x04  |    96B     |  ClientGenerateKE1
  * |  0x05  |   192B     |  ServerGenerateKE2
  * |  0x06  |    64B     |  ClientGenerateKE3
  * |  0x07  |  not-sent  |  ServerFinish
  * |  0x08  |     0B     |  reserved (start-of-communication)
  * |  0x09  |     0B     |  reserved (end-of-communication)
  * #--------#------------#-------------------------------
  *
  * LEGEND:
  * code      - message code
  * size      - size of payload
  * msg type  - type of message

**/
#include "server_side.h"

#define PORT 4444


int main(){

	int sockfd;
	struct sockaddr_in serverAddr;

	int newSocket;
	struct sockaddr_in newAddr;

	socklen_t addr_size;
	uint8_t buffer[1024];
	uint8_t sBuf[1024];
	memset(buffer, 0, 1024);
	memset(sBuf, 0, 1024);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	printf("[+]Server Socket Created Sucessfully.\n");
	memset(&serverAddr, '\0', sizeof(serverAddr));

	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(PORT);
	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

	bind(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
	printf("[+]Bind to Port number %d.\n", PORT);

	listen(sockfd, 5);
	printf("[+]Listening...\n");

  addr_size = sizeof(newAddr);
	newSocket = accept(sockfd, (struct sockaddr*)&newAddr, &addr_size);
  if (newSocket ==-1){
    printf("Oh dear, something went wrong with read()! %s\n", strerror(errno));
  }
  buffer[0] = 0x08;
  uint8_t msg[6] = "/start";
	memcpy(&buffer[1], msg,6);
  printf("buffer:\n");
  print_32(buffer);
	send(newSocket, buffer, sizeof buffer, 0);
  int hasMsg = 0;

	while(sBuf[0] != 0x09){
    memset(buffer, 0, 1024);
    memset(sBuf, 0, 1024);

		hasMsg = recv(newSocket, sBuf, 1024, 0); // perform only if smth is received
    if (hasMsg>0) {
      printf("[M]Message received from Client:\n");
    }

		if (sBuf[0] == 0x04){
      print_32(sBuf);
			printf("[+]Sending AKE2.\n");
      buffer[0] = 0x05;
      uint8_t msg1[4] = "AKE2";
      memcpy(&buffer[1], msg1, 4);
			send(newSocket, buffer, sizeof buffer, 0);

		}

		if (sBuf[0] == 0x06){
      print_32(sBuf);
      printf("[+]Quitting communication.\n");
      buffer[0] = 0x09;
      uint8_t msg2[5] = "/quit";
      memcpy(&buffer[1], msg2, 5);
			send(newSocket, buffer, sizeof buffer, 0);
		}

		

	}
	printf("[+]Closing the connection.\n");
	exit(0);
	return 0;
}