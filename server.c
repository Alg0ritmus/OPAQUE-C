#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>


// OPAQUE
#include "server_side.h"

#define PORT 4444


int main(){

	int sockfd;
	struct sockaddr_in serverAddr;

	int newSocket;
	struct sockaddr_in newAddr;

	socklen_t addr_size;
	char buffer[1024];
	char sBuf[1024];
	memset(buffer, '\0', 1024);
	memset(sBuf, '\0', 1024);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	printf("[+]Server Socket Created Sucessfully.\n");
	memset(&serverAddr, '\0', sizeof(serverAddr));

	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(PORT);
	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

	bind(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
	printf("[+]Bind to Port number %d.\n", 4455);

	listen(sockfd, 5);
	printf("[+]Listening...\n");

	newSocket = accept(sockfd, (struct sockaddr*)&newAddr, &addr_size);

	strcpy(buffer, "/start");
	send(newSocket, buffer, strlen(buffer), 0);

	while(strcmp(sBuf,"/quit") != 0){

		recv(newSocket, sBuf, 1024, 0);
		printf("tGOT:%s\n",sBuf);

		if (strcmp(sBuf,"AKE1 from Client")== 0){
			printf("GOT:%s\n",sBuf);
			printf("sending AKE2\n");
			strcpy(buffer, "AKE2");
			send(newSocket, buffer, strlen(buffer), 0);

		}

		recv(newSocket, sBuf, 1024, 0);

		if (strcmp(sBuf,"AKE3 from Client")== 0){
			strcpy(buffer, "/quit");
			send(newSocket, buffer, strlen(buffer), 0);
			exit(0);
		}

		memset(buffer, '\0', 1024);
		memset(sBuf, '\0', 1024);

	}
	printf("[+]Closing the connection.\n");
	exit(0);
	return 0;
}