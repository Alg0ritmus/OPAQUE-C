#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// OPAQUE


/**
  * MSG idea:
  * #--------#---------#
  * | header | payload |
  * #--------#---------#
**/


/** message type-header table
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
#include "client_side.h"

#define PORT 4444

int main(){
	
	int clientSocket;
	struct sockaddr_in serverAddr;
	uint8_t buffer[1024];
	uint8_t sBuf[1024];
	memset(buffer, 0, 1024);
	memset(sBuf, 0, 1024);

	clientSocket = socket(PF_INET, SOCK_STREAM, 0);
	printf("[+]Client Socket Created Sucessfully.\n");

	memset(&serverAddr, '\0', sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(PORT);
	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

	connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
	printf("[+]Connected to Server.\n");

	int hasMsg = 0;
	
	while(sBuf[0] != 0x09){

		memset(buffer, 0, 1024);
		memset(sBuf, 0, 1024);

		hasMsg = recv(clientSocket, sBuf, 1024, 0); // perform only if smth is received
		
		if (hasMsg>0){
			printf("[M]Message received from Server:\n");
			print_32(sBuf);
		}

		if (sBuf[0] == 0x08){ // start-of-communication
			printf("[+]Sending AKE1.\n");
			// set header (first byte)
			buffer[0] = 0x04;
			// set payload (body)
			uint8_t msg1[16] = "AKE1 from Client";
			memcpy(&buffer[1], msg1, 16);
			send(clientSocket, buffer, sizeof buffer, 0);

		}

		if (sBuf[0] == 0x05){
			print_32(sBuf);
			printf("[+]Sending AKE3.\n");
			// set header (first byte)
			buffer[0] = 0x06;
			// set payload (body)
			uint8_t msg2[16] = "AKE3 from Client";
			memcpy(&buffer[1], msg2, 16);
			send(clientSocket, buffer, sizeof buffer, 0);

		}

		if (sBuf[0] == 0x09) {
			buffer[0] = 0x09;
			send(clientSocket, buffer, sizeof buffer, 0);
			exit(0);
		}
		

		


	}

	printf("[+]Closing the connection.\n");
	
	exit(0);
	return 0;
}