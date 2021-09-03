/*
# Date: 26/01/2019
# Exit.asm
# Author: Daniele Votta
# Description: Exit with no nulls.
# Tested on: i686 GNU/Linux
# Shellcode Length: 5
*/

#include<stdio.h>
#include<string.h>

/*
Disassembly of section .text:

00000000 <_start>:
   0:	31 c0                	xor    eax,eax
   2:	40                   	inc    eax
   3:	cd 80                	int    0x80
======================= POC Daniele Votta =======================
*/

unsigned char shellcode[] = \
"\x31\xc0\x40\xcd\x80";

int main()
{
	printf("Shellcode Length:  %d\n", strlen(shellcode));

	int (*ret)() = (int(*)())shellcode;

	ret();
}