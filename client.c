#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// OPAQUE
#include "client_side.h"

#define PORT 4444

int main(){
	
	int clientSocket;
	struct sockaddr_in serverAddr;
	char buffer[1024];
	char sBuf[1024];
	memset(buffer, '\0', 1024);
	memset(sBuf, '\0', 1024);

	clientSocket = socket(PF_INET, SOCK_STREAM, 0);
	printf("[+]Client Socket Created Sucessfully.\n");

	memset(&serverAddr, '\0', sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(PORT);
	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

	connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
	printf("[+]Connected to Server.\n");

	while(strcmp(sBuf,"/quit") != 0){

		recv(clientSocket, sBuf, 1024, 0);
		printf("GOT:%s\n",sBuf);

		if (strcmp(sBuf,"/start") == 0){
			printf("sending AKE1\n");
			strcpy(buffer, "AKE1 from Client");
			send(clientSocket, buffer, strlen(buffer), 0);

		}

		if (strcmp(sBuf,"AKE2") == 0){
			printf("Got AKE2 from Server\n");
			printf("sending AKE3\n");
			strcpy(buffer, "AKE3 from Client");
			send(clientSocket, buffer, strlen(buffer), 0);

		}

		if (strcmp(sBuf,"/quit") == 0) {exit(0);}
		memset(buffer, '\0', 1024);
		memset(sBuf, '\0', 1024);

		


	}

	printf("[+]Closing the connection.\n");
	
	exit(0);
	return 0;
}