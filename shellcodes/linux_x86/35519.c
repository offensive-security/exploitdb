/*

Title:  Linux x86  rmdir - 37 bytes
Author:  kw4 <kw4.nop@gmail.com>
useful for testing purposes


 08048060 <_start>:
 8048060:       31 c0                     xor    %eax,%eax
 8048062:       50                          push   %eax
 8048063:       68 6f 6c 68 6f          push   $0x6f686c6f
 8048068:       68 68 6f 6c 68         push   $0x686c6f68
 804806d:       68 2f 68 6f 6c          push   $0x6c6f682f
 8048072:       68 2f 74 6d 70         push   $0x706d742f
 8048077:       89 e3                      mov    %esp,%ebx
 8048079:       b0 28                      mov    $0x28,%al
 804807b:       cd 80                      int    $0x80
 804807d:       31 c0                      xor    %eax,%eax
 804807f:        89 c3                      mov    %eax,%ebx
 8048081:       b0 01                      mov    $0x1,%al
 8048083:       cd 80                      int    $0x80

*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \

"\x31\xc0\x50\x68\x6f\x6c\x68\x6f\x68\x68\x6f\x6c\x68\x68\x2f\x68\x6f\x6c\x68\x2f\x74\x6d\x70\x89\xe3\xb0\x28\xcd\x80\x31\xc0\x89\xc3\xb0\x01\xcd\x80";

main() {

        printf("Shellcode Length:  %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}